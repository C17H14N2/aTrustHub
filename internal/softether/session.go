package softether

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// Session is one connected SoftEther access point. Its tunnel is an
// in-process TCP/IP stack fed by Ethernet frames, so it behaves like the
// aTrust sessions: it can be pooled and routed by the aggregate proxy.
type Session struct {
	client *Client
	stack  *L2Stack
	lease  Lease

	apps []vpn.App
	info vpn.SessionInfo

	closeOnce sync.Once
	done      chan struct{}
	errMu     sync.Mutex
	err       error

	// dialFails counts consecutive failed dials. The gateway's policy timeout
	// is 20 seconds: once a session is older than that, fresh flows time out
	// until it is rebuilt. Rebuilding is cheap (about half a second), so a few
	// failures in a row are treated as a dead session.
	dialFails atomic.Int32
}

// Connect logs in, leases an address and starts the frame pump.
func Connect(ctx context.Context, point model.AccessPoint, creds vpn.Credentials) (*Session, error) {
	cfg := Config{
		Host:               point.Server,
		Port:               point.Port,
		Hub:                point.Hub,
		Username:           point.Username,
		Password:           creds.Login,
		InsecureSkipVerify: true,
	}
	client, err := dialHub(ctx, cfg)
	if err != nil {
		return nil, err
	}

	mac, err := randomMAC()
	if err != nil {
		client.Close()
		return nil, err
	}
	l2, err := NewL2Stack(client.WriteFrame, mac)
	if err != nil {
		client.Close()
		return nil, err
	}

	s := &Session{
		client: client,
		stack:  l2,
		apps:   appsFromCovers(point.Covers),
		done:   make(chan struct{}),
	}

	// Keep the hub's data path warm with a real frame every few seconds.
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				_ = l2.PingGateway()
			}
		}
	}()

	// Pump frames into the stack.
	go func() {
		for {
			frame, err := client.ReadFrame()
			if err != nil {
				s.fail(fmt.Errorf("SoftEther 连接中断：%w", err))
				return
			}
			l2.Deliver(frame)
		}
	}()

	lease, err := l2.AcquireLease(mac, 15*time.Second)
	if err != nil {
		s.Close()
		return nil, err
	}
	// The user's own boundary may add networks the hub did not publish.
	for _, cover := range point.Covers {
		if r, ok := routeFromCover(cover, lease.GW); ok {
			lease.Routes = append(lease.Routes, r)
		}
	}
	if err := l2.Configure(lease); err != nil {
		s.Close()
		return nil, err
	}
	s.lease = lease

	info := vpn.SessionInfo{
		ClientIP: lease.IP.String(),
		Apps:     s.apps,
	}
	if len(lease.Routes) > 0 {
		targets := make([]string, 0, len(lease.Routes))
		for _, r := range lease.Routes {
			targets = append(targets, fmt.Sprintf("%s/%d", r.Dest, r.Prefix))
		}
		info.NodeGroups = targets
	}
	s.info = info
	if lease.Seconds > 0 {
		fmt.Printf("SoftEther DHCP 租约 %d 秒\n", lease.Seconds)
	}

	// The hub's policy sets TimeOut=20: a session with no TCP activity for
	// twenty seconds stops carrying new flows. A probe every eight seconds
	// keeps it alive; it targets the first published network, so the target
	// never has to answer.
	if probe := probeAddress(lease); probe != "" {
		go func() {
			t := time.NewTicker(8 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-s.done:
					return
				case <-t.C:
					ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
					if conn, err := s.Dial(ctx, "tcp", probe); err == nil {
						_ = conn.Close()
					}
					cancel()
				}
			}
		}()
	}
	return s, nil
}

// Dial opens a connection through the tunnel.
func (s *Session) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	select {
	case <-s.done:
		s.errMu.Lock()
		err := s.err
		s.errMu.Unlock()
		if err == nil {
			err = fmt.Errorf("SoftEther 会话已关闭")
		}
		return nil, err
	default:
	}
	var conn net.Conn
	var err error
	if network == "udp" || network == "udp4" {
		conn, err = s.stack.DialUDP(ctx, addr)
	} else {
		conn, err = s.stack.DialContext(ctx, network, addr)
	}
	if err != nil {
		if s.dialFails.Add(1) >= maxDialFailures {
			s.fail(fmt.Errorf("连续 %d 次建连失败，重建会话：%w", maxDialFailures, err))
		}
		return nil, err
	}
	s.dialFails.Store(0)
	return conn, nil
}

// maxDialFailures is how many dials may fail in a row before the session is
// rebuilt. One failure can be a closed port; several mean the tunnel stopped
// carrying new flows.
const maxDialFailures = 2

// Info describes the session for the UI.
func (s *Session) Info() vpn.SessionInfo { return s.info }

// Done reports the end of the tunnel.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is why the tunnel ended, if it did.
func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

// Close tears the session down.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		_ = s.client.Close()
		close(s.done)
	})
	return nil
}

func (s *Session) fail(err error) {
	s.closeOnce.Do(func() {
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		_ = s.client.Close()
		close(s.done)
	})
}

// probeAddress picks a target for the session keep-alive: the first host of
// the first published network, on a port nothing listens on.
func probeAddress(lease Lease) string {
	for _, r := range lease.Routes {
		if r.Dest == nil {
			continue
		}
		host := r.Dest
		if r.Prefix < 32 {
			host = append(net.IP(nil), r.Dest...)
			host[3] = 1
		}
		return fmt.Sprintf("%s:1", host)
	}
	return ""
}

// appsFromCovers turns the user-defined boundary into the app list the
// aggregate router matches on.
func appsFromCovers(covers []string) []vpn.App {
	apps := make([]vpn.App, 0, len(covers))
	for _, cover := range covers {
		cover = strings.TrimSpace(cover)
		if cover == "" {
			continue
		}
		apps = append(apps, vpn.App{
			Name: cover,
			Addresses: []vpn.AppAddress{{
				Protocol: "all",
				Host:     cover,
				Port:     "1-65535",
			}},
		})
	}
	return apps
}

// routeFromCover turns a CIDR/range cover into a stack route.
func routeFromCover(cover string, gw net.IP) (Route, bool) {
	cover = strings.TrimSpace(cover)
	if cover == "" {
		return Route{}, false
	}
	if _, ipnet, err := net.ParseCIDR(cover); err == nil {
		ones, _ := ipnet.Mask.Size()
		return Route{Dest: ipnet.IP.To4(), Prefix: ones, GW: gw}, true
	}
	if ip := net.ParseIP(cover); ip != nil {
		return Route{Dest: ip.To4(), Prefix: 32, GW: gw}, true
	}
	if i := strings.Index(cover, "-"); i > 0 {
		lo := net.ParseIP(strings.TrimSpace(cover[:i]))
		hi := net.ParseIP(strings.TrimSpace(cover[i+1:]))
		if lo != nil && hi != nil {
			// A range is approximated by its enclosing prefix; the aggregate
			// router still matches the exact range, this only widens the route.
			mask := net.CIDRMask(16, 32)
			return Route{Dest: lo.To4().Mask(mask), Prefix: 16, GW: gw}, true
		}
	}
	return Route{}, false
}

func randomMAC() (net.HardwareAddr, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] = 0x5e // locally administered, the prefix SoftEther clients use
	b[1] = 0x00
	return net.HardwareAddr(b), nil
}
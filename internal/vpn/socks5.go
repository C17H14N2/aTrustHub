package vpn

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/qy/easyconnect/internal/model"
)

// Socks5Backend is an external SOCKS5 proxy used as an interim transport for
// VPN products the app cannot speak natively yet. Its application boundary is
// user-defined (AccessPoint.Covers).
type Socks5Backend struct{}

// NewSocks5Backend returns the interim external-SOCKS5 backend.
func NewSocks5Backend() Backend { return Socks5Backend{} }

func (Socks5Backend) Kind() string { return model.KindSocks5 }

func (Socks5Backend) Connect(_ context.Context, point model.AccessPoint, creds Credentials) (Session, error) {
	return newSocks5Session(point, creds)
}

type socks5Session struct {
	server string
	apps   []App
	dialer proxy.Dialer
}

func newSocks5Session(cfg model.AccessPoint, creds Credentials) (*socks5Session, error) {
	if strings.TrimSpace(cfg.Server) == "" || cfg.Port <= 0 {
		return nil, fmt.Errorf("SOCKS5 接入点缺少服务器或端口")
	}
	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))
	var auth *proxy.Auth
	if cfg.Username != "" || creds.Login != "" {
		auth = &proxy.Auth{User: cfg.Username, Password: creds.Login}
	}
	dialer, err := proxy.SOCKS5("tcp", addr, auth, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("创建 SOCKS5 客户端：%w", err)
	}
	return &socks5Session{
		server: addr,
		apps:   coversApps(cfg.Covers),
		dialer: dialer,
	}, nil
}

// coversApps turns the user-defined boundary into one app, so the aggregate's
// candidateCovers (exact domain, CIDR and IP range) works unchanged.
func coversApps(covers []string) []App {
	app := App{Name: "自定义应用边界"}
	for _, cover := range covers {
		cover = strings.TrimSpace(cover)
		if cover == "" {
			continue
		}
		app.Addresses = append(app.Addresses, AppAddress{
			Protocol: "all",
			Host:     cover,
			Port:     "1-65535",
		})
	}
	if len(app.Addresses) == 0 {
		return nil
	}
	return []App{app}
}

func (s *socks5Session) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if cd, ok := s.dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := s.dialer.Dial(network, addr)
		ch <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

func (s *socks5Session) Info() SessionInfo {
	return SessionInfo{Apps: s.apps}
}

func (s *socks5Session) Close() error { return nil }

package softether

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID tcpip.NICID = 1
	mtu   uint32      = 1500
)

// Route is one network the hub publishes, either through DHCP option 121 or
// from the user's own application boundary.
type Route struct {
	Dest   net.IP
	Prefix int
	GW     net.IP
}

// Lease is what the hub handed out.
type Lease struct {
	IP      net.IP
	Prefix  int
	GW      net.IP
	Routes   []Route
	Seconds  int
	ServerID net.IP
}

// L2Stack runs an Ethernet link over the tunnel inside gVisor, so the whole
// TCP/IP stack lives in this process: no utun, no tap, no routes, nothing for
// another VPN client to fight over.
type L2Stack struct {
	ns  *stack.Stack
	eth *ethernet.Endpoint
	l2  *l2Endpoint
	br  *bridge

	mu   sync.Mutex
	ip   tcpip.Address
	gw    net.IP
	gwMAC tcpip.LinkAddress
	routes []Route
}

// NewL2Stack wires an Ethernet endpoint to the given frame writer.
func NewL2Stack(write func([]byte) error, mac net.HardwareAddr) (*L2Stack, error) {
	l2 := &l2Endpoint{mac: tcpip.LinkAddress(mac), mtu: mtu, write: write}
	eth := ethernet.New(l2)
	l2.eth = eth

	ns := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := ns.CreateNIC(nicID, eth); err != nil {
		return nil, fmt.Errorf("创建 gVisor 网卡失败：%s", err)
	}
	ns.SetPromiscuousMode(nicID, true)
	ns.SetSpoofing(nicID, true)

	s := &L2Stack{ns: ns, eth: eth, l2: l2, br: &bridge{}}
	l2.tap = s.br.offer
	return s, nil
}

// Deliver hands one received frame to the stack.
func (s *L2Stack) Deliver(frame []byte) { s.l2.deliver(frame) }

// Configure applies addressing and routes to the user-space stack.
func (s *L2Stack) Configure(lease Lease) error {
	if lease.IP == nil {
		return fmt.Errorf("没有可用的地址")
	}
	prefix := lease.Prefix
	if prefix == 0 {
		prefix = 24
	}
	addr := tcpip.AddrFromSlice(lease.IP.To4())
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: addr, PrefixLen: prefix,
		},
	}
	if err := s.ns.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("配置地址失败：%s", err)
	}

	gw := lease.GW
	if gw == nil && len(lease.Routes) > 0 {
		gw = lease.Routes[0].GW
	}

	s.mu.Lock()
	s.ip = addr
	s.gw = gw
	s.routes = append([]Route(nil), lease.Routes...)
	s.mu.Unlock()

	if gw != nil {
		if mac, ok := s.arpResolve(addr, gw, 5*time.Second); ok {
			s.ns.AddStaticNeighbor(nicID, ipv4.ProtocolNumber, tcpip.AddrFromSlice(gw.To4()), mac)
			s.mu.Lock()
			s.gwMAC = mac
			s.mu.Unlock()
		}
	}

	// Default route through the hub gateway, then the published networks.
	route := tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID}
	if gw != nil {
		route.Gateway = tcpip.AddrFromSlice(gw.To4())
	}
	s.ns.AddRoute(route)
	for _, r := range lease.Routes {
		mask := net.CIDRMask(r.Prefix, 32)
		subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(r.Dest.Mask(mask)), tcpip.MaskFromBytes(mask))
		if err != nil {
			continue
		}
		rr := tcpip.Route{Destination: subnet, NIC: nicID}
		if r.GW != nil {
			rr.Gateway = tcpip.AddrFromSlice(r.GW.To4())
		}
		s.ns.AddRoute(rr)
	}
	return nil
}

// DialContext opens a TCP connection through the user-space stack.
func (s *L2Stack) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4":
	default:
		return nil, fmt.Errorf("SoftEther 隧道只支持 TCP（收到 %s）", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("端口无效：%s", portStr)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		// The tunnel has no resolver of its own; callers resolve first.
		return nil, fmt.Errorf("SoftEther 隧道需要 IPv4 目标：%s", host)
	}
	s.mu.Lock()
	src, gw := s.ip, s.gw
	s.mu.Unlock()
	full := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(ip), Port: uint16(port)}

	conn, err := gonet.DialContextTCP(ctx, s.ns, full, ipv4.ProtocolNumber)
	if err == nil {
		return conn, nil
	}
	// Retry once after refreshing the gateway entry.
	if gw != nil && src != (tcpip.Address{}) {
		if mac, ok := s.arpResolve(src, gw, 3*time.Second); ok {
			s.ns.AddStaticNeighbor(nicID, ipv4.ProtocolNumber, tcpip.AddrFromSlice(gw.To4()), mac)
			return gonet.DialContextTCP(ctx, s.ns, full, ipv4.ProtocolNumber)
		}
	}
	return nil, err
}

// DialUDP opens a UDP socket through the user-space stack.
func (s *L2Stack) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("端口无效：%s", portStr)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("SoftEther 隧道需要 IPv4 目标：%s", host)
	}
	full := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(ip), Port: uint16(port)}
	return gonet.DialUDP(s.ns, nil, &full, ipv4.ProtocolNumber)
}

// --- link endpoint ---

type l2Endpoint struct {
	dispatcher stack.NetworkDispatcher
	mac        tcpip.LinkAddress
	mtu        uint32
	write      func([]byte) error
	eth        *ethernet.Endpoint
	tap        func([]byte)
}

func (e *l2Endpoint) MTU() uint32                       { return e.mtu }
func (e *l2Endpoint) SetMTU(m uint32)                   { e.mtu = m }
func (e *l2Endpoint) MaxHeaderLength() uint16           { return header.EthernetMinimumSize }
func (e *l2Endpoint) LinkAddress() tcpip.LinkAddress    { return e.mac }
func (e *l2Endpoint) SetLinkAddress(a tcpip.LinkAddress) { e.mac = a }
func (e *l2Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired
}
func (e *l2Endpoint) Attach(d stack.NetworkDispatcher) { e.dispatcher = d }
func (e *l2Endpoint) IsAttached() bool                 { return e.dispatcher != nil }
func (e *l2Endpoint) Wait()                            {}
func (e *l2Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}
func (e *l2Endpoint) AddHeader(*stack.PacketBuffer) {}
func (e *l2Endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }
func (e *l2Endpoint) Close()                        {}
func (e *l2Endpoint) SetOnCloseAction(func())       {}

func (e *l2Endpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range list.AsSlice() {
		var slices [][]byte
		slices = append(slices, pkt.AsSlices()...)
		var frame []byte
		for _, s := range slices {
			frame = append(frame, s...)
		}
		if len(frame) == 0 {
			continue
		}
		if err := e.write(frame); err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}

// deliver passes a received frame to the ethernet endpoint. The endpoint
// consumes the link header itself, so the frame stays whole in the payload.
//
// It must never block: it runs on the tunnel reader, and a stall here stops
// reads, fills the TCP window and makes the hub stop sending. Slow deliveries
// are logged so a regression is visible.
func (e *l2Endpoint) deliver(frame []byte) {
	if e.eth == nil || !e.eth.IsAttached() {
		return
	}
	if e.tap != nil {
		e.tap(frame)
	}
	start := time.Now()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer pkt.DecRef()
	e.eth.DeliverNetworkPacket(0, pkt)
	if d := time.Since(start); d > 200*time.Millisecond {
		fmt.Printf("deliver slow: %s (%d bytes, ethertype=0x%02x%02x)\n",
			d.Round(time.Millisecond), len(frame), frame[12], frame[13])
	}
}


// PingGatewayICMP sends an ICMP echo request to the gateway. Unlike ARP this is
// a unicast frame, so it does not spend the hub's broadcast budget, and unlike
// the TLS keep-alive it is a real Ethernet frame that the hub counts as session
// traffic.
func (s *L2Stack) PingGatewayICMP(seq uint16) error {
	s.mu.Lock()
	srcIP, gwIP := s.ip, s.gw
	gwMAC := s.gwMAC
	s.mu.Unlock()
	if gwIP == nil || srcIP == (tcpip.Address{}) || len(gwMAC) == 0 {
		return nil
	}

	src4 := srcIP.As4()
	icmp := make([]byte, 8+16) // header + payload
	icmp[0] = 8                // echo request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:], 0x1234)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	for i := 8; i < len(icmp); i++ {
		icmp[i] = byte(i)
	}
	binary.BigEndian.PutUint16(icmp[2:], ipChecksum(icmp))

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(icmp)))
	binary.BigEndian.PutUint16(ip[4:], seq)
	ip[8] = 64
	ip[9] = 1 // ICMP
	copy(ip[12:16], src4[:])
	copy(ip[16:20], gwIP.To4())
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))

	eth := make([]byte, 14)
	copy(eth[0:6], gwMAC)
	copy(eth[6:12], src4[:])
	eth[12], eth[13] = 0x08, 0x00

	frame := append(append(append(eth, ip...), icmp...), make([]byte, 6)...) // pad to 60
	return s.l2.write(frame)
}

// PingGateway sends one ARP request for the gateway. A real frame keeps the
// hub's data path alive in a way the control-stream keep-alive does not.
func (s *L2Stack) PingGateway() error {
	s.mu.Lock()
	src, gw := s.ip, s.gw
	s.mu.Unlock()
	if gw == nil || src == (tcpip.Address{}) {
		return nil
	}
	src4 := src.As4()
	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], src4[:])
	frame[12], frame[13] = 0x08, 0x06
	frame[14], frame[15] = 0x00, 0x01
	frame[16], frame[17] = 0x08, 0x00
	frame[18], frame[19] = 6, 4
	frame[20], frame[21] = 0x00, 0x01
	copy(frame[22:28], src4[:])
	copy(frame[28:32], src4[:])
	binary.BigEndian.PutUint32(frame[38:], binary.BigEndian.Uint32(gw.To4()))
	return s.l2.write(frame)
}

// arpResolve broadcasts an ARP request and waits for the reply.
func (s *L2Stack) arpResolve(src tcpip.Address, target net.IP, timeout time.Duration) (tcpip.LinkAddress, bool) {
	src4 := src.As4()
	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], src4[:])
	frame[12], frame[13] = 0x08, 0x06
	frame[14], frame[15] = 0x00, 0x01
	frame[16], frame[17] = 0x08, 0x00
	frame[18], frame[19] = 6, 4
	frame[20], frame[21] = 0x00, 0x01
	copy(frame[22:28], src4[:])
	copy(frame[28:32], src4[:])
	binary.BigEndian.PutUint32(frame[38:], binary.BigEndian.Uint32(target.To4()))

	if err := s.l2.write(frame); err != nil {
		return "", false
	}

	ch := s.br.watch()
	defer s.br.unwatch(ch)

	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return "", false
		case f := <-ch:
			if len(f) < 42 || binary.BigEndian.Uint16(f[12:14]) != 0x0806 {
				continue
			}
			if binary.BigEndian.Uint16(f[20:22]) != 0x0002 {
				continue
			}
			if binary.BigEndian.Uint32(f[28:32]) != binary.BigEndian.Uint32(target.To4()) {
				continue
			}
			return tcpip.LinkAddress(f[22:28]), true
		}
	}
}

// bridge fans incoming frames out to whoever is watching (DHCP, ARP), without
// blocking the receive loop.
type bridge struct {
	mu      sync.Mutex
	watcher chan []byte
}

func (b *bridge) offer(frame []byte) {
	b.mu.Lock()
	ch := b.watcher
	b.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- frame:
	default:
	}
}

func (b *bridge) watch() chan []byte {
	ch := make(chan []byte, 64)
	b.mu.Lock()
	b.watcher = ch
	b.mu.Unlock()
	return ch
}

func (b *bridge) unwatch(ch chan []byte) {
	b.mu.Lock()
	if b.watcher == ch {
		b.watcher = nil
	}
	b.mu.Unlock()
	close(ch)
}
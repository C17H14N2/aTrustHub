//go:build !android

package tun

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/internal/zctcpip"
)

func TestRedirectTargetMatches(t *testing.T) {
	s := &Stack{}
	s.SetupRedirects(map[string]string{
		"210.76.17.0:3306": "127.0.0.1:33060",
		"10.9.9.9":         "127.0.0.1:9000", // bare IP covers every port
	})

	cases := []struct {
		ip   string
		port int
		want string
		ok   bool
	}{
		{"210.76.17.0", 3306, "127.0.0.1:33060", true},
		{"210.76.17.0", 3305, "", false},   // port-specific rule does not cover others
		{"10.9.9.9", 1234, "127.0.0.1:9000", true},
		{"10.9.9.9", 65535, "127.0.0.1:9000", true},
		{"210.76.17.1", 3306, "", false},   // different IP
	}
	for _, c := range cases {
		got, ok := s.redirectTarget(net.ParseIP(c.ip), c.port)
		if ok != c.ok || got != c.want {
			t.Errorf("redirectTarget(%s,%d) = (%q,%v), want (%q,%v)", c.ip, c.port, got, ok, c.want, c.ok)
		}
	}
}

func TestRedirectTargetEmpty(t *testing.T) {
	s := &Stack{}
	if _, ok := s.redirectTarget(net.ParseIP("210.76.17.0"), 3306); ok {
		t.Fatal("no table should match nothing")
	}
	// Empty/whitespace entries are dropped.
	s.SetupRedirects(map[string]string{"": "x", " ": "y", "1.2.3.4": ""})
	if len(s.redirects) != 0 {
		t.Fatalf("blank entries kept: %v", s.redirects)
	}
}

// TestHandleInboundConnRedirectsToLocal wires the redirect path end to end: an
// inbound TUN-side conn for a redirected target must reach the local listener
// and carry bytes both ways, without any VPN client in play.
func TestHandleInboundConnRedirectsToLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 5)
		n, _ := io.ReadFull(c, buf)
		got <- string(buf[:n])
		_, _ = c.Write([]byte("PONG!"))
	}()

	s := &Stack{}
	s.SetupRedirects(map[string]string{"210.76.17.0:3306": ln.Addr().String()})

	// A pipe stands in for the gvisor endpoint's net.Conn on the TUN side.
	clientSide, serverSide := net.Pipe()
	go s.handleInboundConn(serverSide, "210.76.17.0", 3306)

	_ = clientSide.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := clientSide.Write([]byte("HELLO")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "PONG!" {
		t.Fatalf("reply = %q, want PONG!", reply)
	}
	select {
	case v := <-got:
		if v != "HELLO" {
			t.Fatalf("local server got %q, want HELLO", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("local server never received the payload")
	}
	_ = clientSide.Close()
}

// 映射模式下的栈没有 resolver、没有 fake-IP 池：处理包时不能 panic，
// 否则 helper 崩溃会把整机 DNS/路由留在半成品状态（曾经导致断网）。
func TestProcessIPV4WithoutResolverOrPoolDoesNotPanic(t *testing.T) {
	s := &Stack{} // resolve == nil, ipPool == nil

	// 构造一个发往 127.0.0.1:53 的 UDP DNS 包。
	pkt := make([]byte, 28)
	pkt[0] = 0x45 // IPv4, IHL=5
	pkt[2], pkt[3] = 0x00, 0x1c // total length 28
	pkt[9] = 17   // UDP
	copy(pkt[12:16], []byte{198, 18, 250, 2}) // src
	copy(pkt[16:20], []byte{114, 114, 114, 114}) // dst
	udp := pkt[20:]
	udp[0], udp[1] = 0x30, 0x39 // src port 12345
	udp[2], udp[3] = 0x00, 0x35 // dst port 53
	udp[4], udp[5] = 0x00, 0x08

	ip := zctcpip.IPv4Packet(pkt)
	u := zctcpip.UDPPacket(ip.Payload())

	if got := s.shouldHijackUDPDns(ip, u); got {
		t.Fatal("没有 resolver 时不该劫持 DNS")
	}
	// 不应 panic（会返回「无资源」之类错误，可以忽略）。
	_ = s.processIPV4(ip)
}

// TCP 重定向在映射模式下必须命中，即便没有 ipPool。
func TestProcessIPV4RedirectWithoutPool(t *testing.T) {
	s := &Stack{}
	s.SetupRedirects(map[string]string{"210.76.17.0:3306": "127.0.0.1:33060"})
	if _, ok := s.redirectTarget(net.ParseIP("210.76.17.0"), 3306); !ok {
		t.Fatal("重定向规则未命中")
	}
}

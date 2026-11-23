package tcptunnel

import (
	"context"
	"fmt"
	"net"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	// SPIKE: 不再因为 EnableTCPPrefL3=true 拒绝。这类资源在 L3 下会因为
	// 认证请求不带 domain 被网关拒绝，反而只能靠 TCP 隧道把域名交给网关解析。
	if s.client.CanUseTCPTunnel() {
		return s.client.DialTCP(ctx, addr)
	}

	return nil, fmt.Errorf("not implemented")
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}

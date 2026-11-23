package softether

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// dhcpDiscover builds an Ethernet/IPv4/UDP DHCP DISCOVER.
func dhcpDiscover(mac net.HardwareAddr) []byte {
	return dhcpRequest(mac, 1) // 1 = DISCOVER
}

// dhcpRequestMessage builds the REQUEST that confirms the offered address.
func dhcpRequestMessage(mac net.HardwareAddr, offered net.IP) []byte {
	frame := dhcpRequest(mac, 3) // 3 = REQUEST
	// Rewrite the payload with the requested-IP option so the server knows
	// which offer is being accepted.
	d := frame[len(frame)-300:]
	// Trim the parameter list and rebuild options.
	d = d[:240]
	d = append(d, 53, 1, 3) // DHCP Request
	d = append(d, 50, 4, offered[0], offered[1], offered[2], offered[3])
	d = append(d, 55, 3, 1, 3, 6)
	d = append(d, 255)
	for len(d) < 300 {
		d = append(d, 0)
	}
	ip := frame[14:34]
	udp := frame[34:42]
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)+len(d)))
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(d)))
	binary.BigEndian.PutUint16(ip[10:], 0)
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))
	return append(append(append(append([]byte{}, frame[:14]...), ip...), udp...), d...)
}

func dhcpRequest(mac net.HardwareAddr, msgType byte) []byte {
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(eth[6:12], mac)
	eth[12], eth[13] = 0x08, 0x00

	d := make([]byte, 240)
	d[0], d[1], d[2] = 1, 1, 6
	d[4], d[5], d[6], d[7] = 0x12, 0x34, 0x56, 0x78
	copy(d[28:34], mac)
	d[236], d[237], d[238], d[239] = 99, 130, 83, 99
	d = append(d, 53, 1, msgType)
	d = append(d, 55, 3, 1, 3, 6)
	d = append(d, 255)
	for len(d) < 300 {
		d = append(d, 0)
	}

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 68)
	binary.BigEndian.PutUint16(udp[2:], 67)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(d)))

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)+len(d)))
	binary.BigEndian.PutUint16(ip[4:], 0x1234)
	ip[8] = 64
	ip[9] = 17
	copy(ip[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))

	return append(append(append(eth, ip...), udp...), d...)
}

func ipChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

// parseDHCP reads a DHCP reply out of an Ethernet frame, including the
// classless static routes (option 121) this hub family uses to publish its
// internal networks.
func parseDHCP(frame []byte) (lease Lease, msgType byte, ok bool) {
	if len(frame) < 14+20+8+240 {
		return Lease{}, 0, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 || frame[23] != 17 {
		return Lease{}, 0, false
	}
	d := frame[14+20+8:]
	if d[0] != 2 { // BOOTREPLY
		return Lease{}, 0, false
	}
	lease.IP = net.IPv4(d[16], d[17], d[18], d[19]).To4()
	server := net.IPv4(d[20], d[21], d[22], d[23]).To4()
	lease.Prefix = 24

	opts := d[240:]
	for i := 0; i+1 < len(opts); {
		code, size := opts[i], int(opts[i+1])
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+2+size > len(opts) {
			break
		}
		v := opts[i+2 : i+2+size]
		switch code {
		case 53:
			if size >= 1 {
				msgType = v[0]
			}
		case 1:
			if size >= 4 {
				mask := binary.BigEndian.Uint32(v[:4])
				lease.Prefix = 0
				for mask != 0 {
					lease.Prefix++
					mask <<= 1
				}
			}
		case 3:
			if size >= 4 {
				lease.GW = net.IPv4(v[0], v[1], v[2], v[3]).To4()
			}
		case 121:
			for j := 0; j+1 < len(v); {
				width := int(v[j])
				j++
				if width > 32 {
					break
				}
				nBytes := (width + 7) / 8
				if j+nBytes+4 > len(v) {
					break
				}
				dest := make(net.IP, 4)
				copy(dest, v[j:j+nBytes])
				j += nBytes
				gw := net.IPv4(v[j], v[j+1], v[j+2], v[j+3]).To4()
				j += 4
				lease.Routes = append(lease.Routes, Route{Dest: dest, Prefix: width, GW: gw})
			}
		}
		i += 2 + size
	}
	if lease.GW == nil && !server.Equal(net.IPv4zero) {
		// The hub often omits the router option; its server address is the
		// gateway in that case.
		lease.GW = server
	}
	// The routes the hub pushes point at the real next hop, which is not
	// always the router option.
	if len(lease.Routes) > 0 && lease.Routes[0].GW != nil {
		lease.GW = lease.Routes[0].GW
	}
	return lease, msgType, lease.IP != nil && !lease.IP.Equal(net.IPv4zero)
}

// AcquireLease runs a minimal DHCP handshake over the tunnel.
func (s *L2Stack) AcquireLease(mac net.HardwareAddr, timeout time.Duration) (Lease, error) {
	if err := s.l2.write(dhcpDiscover(mac)); err != nil {
		return Lease{}, fmt.Errorf("发送 DHCP DISCOVER 失败：%w", err)
	}
	ch := s.br.watch()
	defer s.br.unwatch(ch)

	deadline := time.After(timeout)
	var offered Lease
	for {
		select {
		case <-deadline:
			if offered.IP != nil {
				return offered, nil
			}
			return Lease{}, fmt.Errorf("等待 DHCP 响应超时")
		case f := <-ch:
			lease, msgType, ok := parseDHCP(f)
			if !ok {
				continue
			}
			switch msgType {
			case 2: // OFFER
				offered = lease
				// Confirm the offer before returning.
				if err := s.l2.write(dhcpRequestMessage(mac, lease.IP)); err != nil {
					return lease, nil
				}
			case 5: // ACK
				if lease.IP == nil {
					lease = offered
				}
				return lease, nil
			}
		}
	}
}
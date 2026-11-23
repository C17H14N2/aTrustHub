package softether

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/qy/easyconnect/internal/softether/cedar"
	"github.com/qy/easyconnect/internal/softether/mayaqua"
)

// keepAliveMagic marks a keep-alive record on the tunnel stream.
const keepAliveMagic uint32 = 0xffffffff

// Config is everything needed to reach one SoftEther hub.
type Config struct {
	Host     string
	Port     int
	Hub      string
	Username string
	Password string
	// InsecureSkipVerify accepts the self-signed certificate these gateways
	// use. The session is still encrypted; only the certificate identity is
	// unchecked, which matches what the official client does by default.
	InsecureSkipVerify bool
}

// Client is one authenticated SoftEther session carrying Ethernet frames.
// Nothing here touches the operating system: frames go in and out over the
// TLS stream, and the L2 stack runs in user space.
type Client struct {
	sock *mayaqua.Sock
	cfg  Config

	writeMu sync.Mutex
	closed  bool
}

// dialHub authenticates against the hub and switches the stream to tunneling
// mode, ready for Ethernet frames.
func dialHub(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Hub == "" || cfg.Username == "" {
		return nil, errors.New("SoftEther 需要虚拟 HUB 名和用户名")
	}

	type result struct {
		c   *Client
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := connectSync(cfg)
		done <- result{c: c, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		return r.c, r.err
	}
}

func connectSync(cfg Config) (*Client, error) {
	sum := mayaqua.Sha0([]byte(cfg.Password + strings.ToUpper(cfg.Username)))

	sess := cedar.Session{}
	sess.ClientAuth.AuthType = cedar.CLIENT_AUTHTYPE_PASSWORD
	sess.ClientAuth.Username = cfg.Username
	copy(sess.ClientAuth.HashedPassword[:], sum[:])

	conn := cedar.Connection{
		Cedar:              cedar.NewCedar(),
		Host:               cfg.Host,
		Port:               cfg.Port,
		ClientVer:          clientVersion,
		ClientBuild:        clientBuild,
		ClientStr:          clientString,
		Session:            &sess,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	sess.Connection = &conn

	sock, err := conn.ClientConnectToServer()
	if err != nil {
		return nil, fmt.Errorf("连接 SoftEther 服务器失败：%w", err)
	}
	req, err := conn.ClientUploadSignature(sock)
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("SoftEther 签名交换失败：%w", err)
	}
	if err := conn.ClientDownloadHello(sock, req); err != nil {
		sock.Close()
		return nil, fmt.Errorf("SoftEther 握手失败：%w", err)
	}

	// The login packet is built by hand: this hub family rejects the newer
	// NodeInfo/WinVer structures with ERR_PROTOCOL_ERROR, so only the fields
	// an old client sends are included.
	securePassword := cedar.SecurePassword(sess.ClientAuth.HashedPassword, mayaqua.Sha1Sum(conn.Random))
	pack := cedar.PackLoginWithPassword(cfg.Hub, cfg.Username, securePassword)
	pack.AddStr("client_str", clientString)
	pack.AddInt("client_ver", clientVersion)
	pack.AddInt("client_build", clientBuild)
	pack.AddInt("protocol", uint32(cedar.CONNECTION_TCP))
	pack.AddInt("max_connection", 1)
	pack.AddBool("use_encrypt", true)
	pack.AddBool("use_compress", false)
	pack.AddBool("half_connection", false)
	pack.AddBool("require_bridge_routing_mode", false)
	pack.AddBool("require_monitor_mode", false)
	pack.AddBool("qos", true)

	authReq, err := mayaqua.HttpClientSend(sock, pack)
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("SoftEther 认证请求失败：%w", err)
	}
	welcome, err := mayaqua.HttpClientRecv(sock, authReq)
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("SoftEther 认证响应失败：%w", err)
	}
	if code := welcome.GetError(); code != 0 {
		sock.Close()
		return nil, fmt.Errorf("SoftEther 认证被拒绝：%s", cedar.ErrorCode(code))
	}

	sessionName, connectionName, _ := cedar.ParseWelcomeFromPack(welcome)
	key, key32, err := cedar.GetSessionKeyFromPack(welcome)
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("SoftEther 会话密钥失败：%w", err)
	}
	if welcome.GetInt("use_encrypt") == 0 {
		sock.Close()
		return nil, errors.New("SoftEther 服务器未启用加密")
	}
	conn.Session.SessionKey = key
	conn.Session.SessionKey32 = key32
	conn.Name = connectionName
	conn.Session.Name = sessionName
	conn.StartTunnelingMode()

	return &Client{sock: sock, cfg: cfg}, nil
}

// Client version reported to the server. The official build numbers work
// across this hub family; the value is informational only.
const (
	clientVersion uint32 = 501
	clientBuild   uint32 = 9674
)

const clientString = "SoftEther VPN Client"

// WriteFrame sends one Ethernet frame.
func (c *Client) WriteFrame(frame []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return errors.New("SoftEther 连接已关闭")
	}
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:], 1) // one packet per record
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(frame)))
	if _, err := c.sock.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.sock.Write(frame)
	return err
}

// ReadFrame returns the next Ethernet frame, skipping keep-alives.
func (c *Client) ReadFrame() ([]byte, error) {
	for {
		var count uint32
		if err := binary.Read(c.sock, binary.BigEndian, &count); err != nil {
			return nil, err
		}
		if count == keepAliveMagic {
			var size uint32
			if err := binary.Read(c.sock, binary.BigEndian, &size); err != nil {
				return nil, err
			}
			if _, err := io.CopyN(io.Discard, c.sock, int64(size)); err != nil {
				return nil, err
			}
			continue
		}
		if count == 0 {
			continue
		}
		var size uint32
		if err := binary.Read(c.sock, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		frame := make([]byte, size)
		if _, err := io.ReadFull(c.sock, frame); err != nil {
			return nil, err
		}
		// Records can carry several packets; this client never batches, so
		// anything beyond the first is dropped rather than misframed.
		return frame, nil
	}
}

// SetReadDeadline bounds ReadFrame, for shutdown.
func (c *Client) SetReadDeadline(t time.Time) error {
	if d, ok := interface{}(c.sock).(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

// Close tears the tunnel down.
func (c *Client) Close() error {
	c.writeMu.Lock()
	if c.closed {
		c.writeMu.Unlock()
		return nil
	}
	c.closed = true
	c.writeMu.Unlock()
	return c.sock.Close()
}
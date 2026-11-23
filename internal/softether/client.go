package softether

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"os"
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
	// ctrl carries authentication and keep-alives; data carries Ethernet
	// frames. The hub expects two: a single connection works for about
	// thirty seconds and then silently stops forwarding new flows.
	ctrl *mayaqua.Sock
	data *mayaqua.Sock
	cfg  Config

	writeMu sync.Mutex
	closed  bool
	done    chan struct{}
	once    sync.Once
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
	pack.AddInt("max_connection", maxConnections)
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
	if granted := welcome.GetInt("max_connection"); granted > 0 {
		fmt.Printf("SoftEther 服务器允许并发连接数：%d\n", granted)
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

	// A second connection can be bound with additional_connect, but this hub
	// answers it with EOF, so the data path shares the control connection.
	/// Until that handshake is understood, one connection carries both.
	dataSock := sock
	if os.Getenv("SOFTETHER_DUAL") == "1" {
		if second, derr := openDataChannel(&conn, cfg); derr == nil {
			dataSock = second
		} else {
			fmt.Println("数据连接未建立，回退单连接：", derr)
		}
	}

	c := &Client{ctrl: sock, data: dataSock, cfg: cfg, done: make(chan struct{})}
	c.startKeepAlive()
	return c, nil
}

// openDataChannel opens the second TLS connection and binds it to the session
// with additional_connect.
func openDataChannel(auth *cedar.Connection, cfg Config) (*mayaqua.Sock, error) {
	second := cedar.Connection{
		Cedar:              cedar.NewCedar(),
		Host:               cfg.Host,
		Port:               cfg.Port,
		ClientVer:          clientVersion,
		ClientBuild:        clientBuild,
		ClientStr:          clientString,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	second.Session = auth.Session

	sock, err := second.ClientConnectToServer()
	if err != nil {
		return nil, fmt.Errorf("建立数据连接失败：%w", err)
	}

	pack := &mayaqua.Pack{}
	pack.AddStr("method", "additional_connect")
	pack.AddData("session_key", auth.Session.SessionKey[:])
	pack.AddStr("client_str", clientString)
	pack.AddInt("client_ver", clientVersion)
	pack.AddInt("client_build", clientBuild)

	req, err := mayaqua.HttpClientSend(sock, pack)
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("数据连接认证请求失败：%w", err)
	}
	resp, err := mayaqua.HttpClientRecv(sock, req)
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("数据连接认证失败：%w", err)
	}
	if code := resp.GetError(); code != 0 {
		sock.Close()
		return nil, fmt.Errorf("数据连接被拒绝：%s", cedar.ErrorCode(code))
	}
	return sock, nil
}

// keepAliveInterval is how often the tunnel sends a keep-alive record. Without
// it the hub drops the session after its idle timeout (about 30 seconds),
// which surfaces as an unexpected EOF on the read loop.
const keepAliveInterval = 5 * time.Second

func (c *Client) startKeepAlive() {
	go func() {
		t := time.NewTicker(keepAliveInterval)
		defer t.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-t.C:
				if err := c.writeKeepAlive(); err != nil {
					return
				}
			}
		}
	}()
}

// writeKeepAlive sends one keep-alive record. The payload is not empty: the
// hub ignores zero-length keep-alives and then drops the data path after its
// idle timeout, which shows up as every dial timing out while the session
// itself stays up.
func (c *Client) writeKeepAlive() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return errors.New("SoftEther 连接已关闭")
	}
	payload := make([]byte, 32)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:], keepAliveMagic)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
	if _, err := c.ctrl.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.ctrl.Write(payload)
	return err
}

// Client version reported to the server. The official build numbers work
// across this hub family; the value is informational only.
const (
	clientVersion uint32 = 501
	clientBuild   uint32 = 9674
)

const clientString = "SoftEther VPN Client"

// maxConnections is how many concurrent TCP streams the tunnel announces.
// The hub honours this as a hard ceiling: with 1, every dial after the first
// times out even though the session itself is healthy.
const maxConnections = 32

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
	if _, err := c.data.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.data.Write(frame)
	return err
}

// ReadFrame returns the next Ethernet frame, skipping keep-alives.
func (c *Client) ReadFrame() ([]byte, error) {
	for {
		var count uint32
		if err := binary.Read(c.data, binary.BigEndian, &count); err != nil {
			return nil, err
		}
		if count == keepAliveMagic {
			var size uint32
			if err := binary.Read(c.data, binary.BigEndian, &size); err != nil {
				return nil, err
			}
			if _, err := io.CopyN(io.Discard, c.data, int64(size)); err != nil {
				return nil, err
			}
			continue
		}
		if count == 0 {
			continue
		}
		var size uint32
		if err := binary.Read(c.data, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		frame := make([]byte, size)
		if _, err := io.ReadFull(c.data, frame); err != nil {
			return nil, err
		}
		// Records can carry several packets; this client never batches, so
		// anything beyond the first is dropped rather than misframed.
		return frame, nil
	}
}

// SetReadDeadline bounds ReadFrame, for shutdown.
func (c *Client) SetReadDeadline(t time.Time) error {
	if d, ok := interface{}(c.data).(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

// Close tears the tunnel down.
func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		c.writeMu.Lock()
		c.closed = true
		c.writeMu.Unlock()
		err = c.ctrl.Close()
		if c.data != nil {
			_ = c.data.Close()
		}
	})
	return err
}
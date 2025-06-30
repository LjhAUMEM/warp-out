package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// SimplifiedClientBind 是 ClientBind 的简化版本，兼容 golang.zx2c4.com/wireguard/conn
type SimplifiedClientBind struct {
	ctx                 context.Context
	bindCtx             context.Context
	bindDone            context.CancelFunc
	dialer              SimplifiedDialer
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	conn                *wireConn
	done                chan struct{}
	isConnect           bool
	connectAddr         netip.AddrPort
	reserved            [3]uint8
}

// SimplifiedDialer 是一个简化的拨号器接口
type SimplifiedDialer interface {
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
	ListenPacket(ctx context.Context, network string, addr string) (net.PacketConn, error)
}

// NewSimplifiedClientBind 创建简化版本的 ClientBind
func NewSimplifiedClientBind(ctx context.Context, dialer SimplifiedDialer, isConnect bool, connectAddr netip.AddrPort, reserved [3]uint8) *SimplifiedClientBind {
	return &SimplifiedClientBind{
		ctx:                 ctx,
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		done:                make(chan struct{}),
		isConnect:           isConnect,
		connectAddr:         connectAddr,
		reserved:            reserved,
	}
}

func (c *SimplifiedClientBind) SetEP(ep netip.AddrPort) {
	c.connectAddr = ep
}

func (c *SimplifiedClientBind) connect() (*wireConn, error) {
	serverConn := c.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	serverConn = c.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	if c.isConnect {
		udpConn, err := c.dialer.DialContext(c.bindCtx, "udp", c.connectAddr.String())
		if err != nil {
			return nil, err
		}
		c.conn = &wireConn{
			PacketConn: &unbindPacketConn{Conn: udpConn},
			done:       make(chan struct{}),
		}
	} else {
		udpConn, err := c.dialer.ListenPacket(c.bindCtx, "udp", ":0")
		if err != nil {
			return nil, err
		}
		c.conn = &wireConn{
			PacketConn: udpConn,
			done:       make(chan struct{}),
		}
	}
	return c.conn, nil
}

func (c *SimplifiedClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	select {
	case <-c.done:
		c.done = make(chan struct{})
	default:
	}
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *SimplifiedClientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (count int, err error) {
	udpConn, err := c.connect()
	if err != nil {
		select {
		case <-c.done:
			return
		default:
		}
		// 简化错误处理，直接返回
		err = nil
		time.Sleep(time.Second)
		return
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if err != nil {
		udpConn.Close()
		select {
		case <-c.done:
		default:
			err = nil
		}
		return
	}
	sizes[0] = n
	if n > 3 {
		b := packets[0]
		// 清除保留字段
		for i := 1; i < 4 && i < len(b); i++ {
			b[i] = 0
		}
	}
	eps[0] = remoteEndpoint(addr.(*net.UDPAddr).AddrPort())
	count = 1
	return
}

func (c *SimplifiedClientBind) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	if c.bindDone != nil {
		c.bindDone()
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

func (c *SimplifiedClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *SimplifiedClientBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	udpConn, err := c.connect()
	if err != nil {
		time.Sleep(time.Second)
		return err
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	for _, b := range bufs {
		if len(b) > 3 {
			reserved, loaded := c.reservedForEndpoint[destination]
			if !loaded {
				reserved = c.reserved
			}
			copy(b[1:4], reserved[:])
		}
		_, err = udpConn.WriteToUDPAddrPort(b, destination)
		if err != nil {
			udpConn.Close()
			return err
		}
	}
	return nil
}

func (c *SimplifiedClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return remoteEndpoint(ap), nil
}

func (c *SimplifiedClientBind) BatchSize() int {
	return 1
}

func (c *SimplifiedClientBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	c.reservedForEndpoint[destination] = reserved
}

// wireConn 包装网络连接
type wireConn struct {
	net.PacketConn
	conn   net.Conn
	access sync.Mutex
	done   chan struct{}
}

func (w *wireConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if w.conn != nil {
		return w.conn.Write(b)
	}
	return w.PacketConn.WriteTo(b, &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Port: int(addr.Port()),
	})
}

func (w *wireConn) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	if w.PacketConn != nil {
		w.PacketConn.Close()
	}
	close(w.done)
	return nil
}

// unbindPacketConn 包装 net.Conn 为 net.PacketConn
type unbindPacketConn struct {
	net.Conn
}

func (u *unbindPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = u.Conn.Read(p)
	if err != nil {
		return 0, nil, err
	}
	// 对于连接模式，返回一个虚拟地址
	addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	return n, addr, nil
}

func (u *unbindPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return u.Conn.Write(p)
}

// remoteEndpoint 实现 conn.Endpoint 接口
type remoteEndpoint netip.AddrPort

func (e remoteEndpoint) ClearSrc() {
}

func (e remoteEndpoint) SrcToString() string {
	return ""
}

func (e remoteEndpoint) DstToString() string {
	return (netip.AddrPort)(e).String()
}

func (e remoteEndpoint) DstToBytes() []byte {
	b, _ := (netip.AddrPort)(e).MarshalBinary()
	return b
}

func (e remoteEndpoint) DstIP() netip.Addr {
	return (netip.AddrPort)(e).Addr()
}

func (e remoteEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// 确保实现接口
var _ conn.Bind = (*SimplifiedClientBind)(nil)
var _ conn.Endpoint = (*remoteEndpoint)(nil)

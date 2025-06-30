package wireguard

import (
	"context"
	"net"
	"net/netip"
	"time"
)

type SimpleDialer struct{}

func (d *SimpleDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

func (d *SimpleDialer) ListenPacket(ctx context.Context, network string, addr string) (net.PacketConn, error) {
	listener := &net.ListenConfig{}
	return listener.ListenPacket(ctx, network, addr)
}

func GetBind(endpoint string, reserved []byte) *SimplifiedClientBind {
	return NewSimplifiedClientBind(
		context.Background(),
		&SimpleDialer{},
		true,
		netip.MustParseAddrPort(endpoint),
		[3]uint8{reserved[0], reserved[1], reserved[2]},
	)
}

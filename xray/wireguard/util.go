package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"a/xray/localdns"

	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/proxy/wireguard/gvisortun"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"

	"golang.zx2c4.com/wireguard/tun"
)

type emptyLogHandler struct{}

func (h *emptyLogHandler) Handle(msg log.Message) {

}

func init() {
	log.RegisterHandler(&emptyLogHandler{})
}

type WireGuardDefaultDialer struct{}

func NewWireGuardDefaultDialer() *WireGuardDefaultDialer {
	return &WireGuardDefaultDialer{}
}

func (d *WireGuardDefaultDialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	return internet.DialSystem(ctx, destination, nil)
}

func (d *WireGuardDefaultDialer) Address() xnet.Address {
	return nil
}

func (d *WireGuardDefaultDialer) DestIpAddress() xnet.IP {
	return nil
}

type SystemDialerAdapter struct {
	systemDialer internet.SystemDialer
}

func NewSystemDialerAdapter() *SystemDialerAdapter {
	return &SystemDialerAdapter{
		systemDialer: &internet.DefaultSystemDialer{},
	}
}

func (a *SystemDialerAdapter) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	conn, err := a.systemDialer.Dial(ctx, nil, destination, nil)
	if err != nil {
		return nil, err
	}
	return stat.Connection(conn), nil
}

func (a *SystemDialerAdapter) Address() xnet.Address {
	return nil
}

func (a *SystemDialerAdapter) DestIpAddress() xnet.IP {
	return a.systemDialer.DestIpAddress()
}

type NetDialerAdapter struct {
	dialer *xnet.Dialer
	destIP xnet.IP
}

func NewNetDialerAdapter(dialer *xnet.Dialer, destIP xnet.IP) *NetDialerAdapter {
	if dialer == nil {
		dialer = &xnet.Dialer{
			Timeout: time.Second * 16, // 默认 16 秒超时
		}
	}
	return &NetDialerAdapter{
		dialer: dialer,
		destIP: destIP,
	}
}

func (a *NetDialerAdapter) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	var conn xnet.Conn
	var err error

	switch destination.Network {
	case xnet.Network_TCP:
		conn, err = a.dialer.DialContext(ctx, "tcp", destination.NetAddr())
	case xnet.Network_UDP:
		conn, err = a.dialer.DialContext(ctx, "udp", destination.NetAddr())
	default:
		return nil, errors.New("unsupported network: " + destination.Network.String())
	}

	if err != nil {
		return nil, err
	}

	return stat.Connection(conn), nil
}

func (a *NetDialerAdapter) Address() xnet.Address {
	if a.dialer.LocalAddr != nil {
		return xnet.ParseAddress(a.dialer.LocalAddr.String())
	}
	return nil
}

func (a *NetDialerAdapter) DestIpAddress() xnet.IP {
	return a.destIP
}

var defaultDialer = &xnet.Dialer{
	Timeout:   time.Second * 16,
	KeepAlive: 30 * time.Second,
}

func GetBind(tunHasIPv4, tunHasIPv6 bool, reserved []byte) *netBindClient {
	return &netBindClient{
		netBind: netBind{
			dns: localdns.New(),
			dnsOption: dns.IPOption{
				IPv4Enable: tunHasIPv4,
				IPv6Enable: tunHasIPv6,
			},
			workers: 1,
		},
		ctx:    context.Background(),
		dialer: NewSystemDialerAdapter(),
		// dialer:   NewNetDialerAdapter(nil, nil),
		reserved: reserved,
	}
}

func GetTun(tunAddrs []string, mtu int) (tun.Device, *gvisortun.Net, *http.Client, error) {
	addrs := make([]netip.Addr, len(tunAddrs))
	for i, str := range tunAddrs {
		var addr netip.Addr
		if strings.Contains(str, "/") {
			prefix, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, nil, nil, err
			}
			addr = prefix.Addr()
			if prefix.Bits() != addr.BitLen() {
				return nil, nil, nil, errors.New("interface address subnet should be /32 for IPv4 and /128 for IPv6")
			}
		} else {
			var err error
			addr, err = netip.ParseAddr(str)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		addrs[i] = addr
	}
	t, tnet, err := createGVisorTun(addrs, mtu, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				switch network {
				case "tcp", "tcp4", "tcp6":
					host, portStr, err := net.SplitHostPort(address)
					if err != nil {
						return nil, err
					}
					port, err := strconv.Atoi(portStr)
					if err != nil {
						return nil, err
					}

					ips, err := net.LookupIP(host)
					if err != nil {
						return nil, err
					}
					if len(ips) == 0 {
						return nil, fmt.Errorf("no IP addresses found for %s", host)
					}

					ip := ips[0]
					ipAddr, err := netip.ParseAddr(ip.String())
					if err != nil {
						return nil, err
					}

					addrPort := netip.AddrPortFrom(ipAddr, uint16(port))
					return tnet.DialContextTCPAddrPort(ctx, addrPort)

				case "udp", "udp4", "udp6":
					host, portStr, err := net.SplitHostPort(address)
					if err != nil {
						return nil, err
					}
					port, err := strconv.Atoi(portStr)
					if err != nil {
						return nil, err
					}

					ips, err := net.LookupIP(host)
					if err != nil {
						return nil, err
					}
					if len(ips) == 0 {
						return nil, fmt.Errorf("no IP addresses found for %s", host)
					}

					ip := ips[0]
					ipAddr, err := netip.ParseAddr(ip.String())
					if err != nil {
						return nil, err
					}

					addrPort := netip.AddrPortFrom(ipAddr, uint16(port))
					return tnet.DialUDPAddrPort(netip.AddrPort{}, addrPort)

				default:
					return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
				}
			},
		},
		Timeout: 1 * time.Second,
	}
	return t, tnet, client, err
}

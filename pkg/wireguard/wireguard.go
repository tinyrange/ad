package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func generateKeyPair() (device.NoisePrivateKey, device.NoisePublicKey, error) {
	var sk device.NoisePrivateKey
	var pk device.NoisePublicKey

	if _, err := rand.Read(sk[:]); err != nil {
		return device.NoisePrivateKey{}, device.NoisePublicKey{}, err
	}

	// Clamp private key.
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64

	// Calculate public key.
	apk := (*[device.NoisePublicKeySize]byte)(&pk)
	ask := (*[device.NoisePrivateKeySize]byte)(&sk)
	curve25519.ScalarBaseMult(apk, ask)

	return sk, pk, nil
}

type Wireguard struct {
	dev       *device.Device
	stack     *Net
	publicKey device.NoisePublicKey
	allowed   []string
	listeners map[string]*listener
}

func (wg *Wireguard) Dial(network string, addr string) (net.Conn, error) {
	return wg.stack.Dial(network, addr)
}

func (wg *Wireguard) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	return wg.stack.DialContext(ctx, network, addr)
}

func (wg *Wireguard) Listen(network string, addr string) (net.Listener, error) {
	if network == "tcp" {
		tcpAddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, err
		}

		return wg.stack.ListenTCP(tcpAddr)
	} else {
		return nil, errors.New("unsupported network")
	}
}

func (wg *Wireguard) Close() error {
	wg.dev.Close()

	return nil
}

func (wg *Wireguard) CreatePeer(publicIp string) (string, error) {
	ipc, err := wg.dev.IpcGet()
	if err != nil {
		return "", err
	}

	var endpoint string

	for _, line := range strings.Split(ipc, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			if line == "" {
				continue
			}
			return "", fmt.Errorf("invalid line: %s", line)
		}

		switch k {
		case "listen_port":
			endpoint = fmt.Sprintf("%s:%s", publicIp, v)
		}
	}

	if endpoint == "" {
		return "", errors.New("missing endpoint")
	}

	sk, pk, err := generateKeyPair()
	if err != nil {
		return "", err
	}

	peerPublicKey := hex.EncodeToString(pk[:])
	privateKey := hex.EncodeToString(sk[:])

	var config []string

	config = append(config, fmt.Sprintf("public_key=%s", peerPublicKey))

	for _, allow := range wg.allowed {
		config = append(config, fmt.Sprintf("allowed_ip=%s", allow))
	}

	if err := wg.dev.IpcSet(strings.Join(config, "\n")); err != nil {
		return "", err
	}

	wg.dev.LookupPeer(pk).Start()

	publicKey := hex.EncodeToString(wg.publicKey[:])

	return fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=0.0.0.0/0
endpoint=%s`, privateKey, publicKey, endpoint), nil
}

func (wg *Wireguard) getListenerForAddr(loc *net.TCPAddr) (*listener, error) {
	// Try a direct match.
	if listen, ok := wg.listeners[loc.String()]; ok {
		return listen, nil
	}

	// Try matching on any port number.
	if listen, ok := wg.listeners[(&net.TCPAddr{
		IP:   loc.IP,
		Port: 0,
	}).String()]; ok {
		return listen, nil
	}

	// Try matching on any IP address.
	if listen, ok := wg.listeners[(&net.TCPAddr{
		IP:   net.IP{0, 0, 0, 0},
		Port: loc.Port,
	}).String()]; ok {
		return listen, nil
	}

	// Fall back to the default root if it exists.
	if listen, ok := wg.listeners[(&net.TCPAddr{
		IP:   net.IP{0, 0, 0, 0},
		Port: 0,
	}).String()]; ok {
		return listen, nil
	}

	return nil, fmt.Errorf("no listener for connection to: %s", loc.String())
}

type listener struct {
	closed bool
	conns  chan *gonet.TCPConn
	addr   *net.TCPAddr
}

// Accept implements net.Listener.
func (l *listener) Accept() (net.Conn, error) {
	if l.closed {
		return nil, net.ErrClosed
	}

	conn := <-l.conns

	return conn, nil
}

// Addr implements net.Listener.
func (l *listener) Addr() net.Addr {
	return l.addr
}

// Close implements net.Listener.
func (l *listener) Close() error {
	if !l.closed {
		l.closed = true
		close(l.conns)
	}

	return nil
}

var (
	_ net.Listener = &listener{}
)

func (wg *Wireguard) ListenTCPAddr(listen string) (net.Listener, error) {
	ip, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}

	ipString := net.ParseIP(ip)
	if ipString == nil {
		return nil, fmt.Errorf("invalid ip: %s", ip)
	}

	portInt, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, err
	}

	listener := &listener{
		addr: net.TCPAddrFromAddrPort(
			netip.AddrPortFrom(
				netip.AddrFrom4([4]byte(ipString.To4())),
				uint16(portInt),
			),
		),
		conns: make(chan *gonet.TCPConn, 8),
	}

	wg.listeners[listener.addr.String()] = listener

	return listener, nil
}

func (wg *Wireguard) handleTcp(r *tcp.ForwarderRequest) {
	id := r.ID()

	var wq waiter.Queue

	ep, ipErr := r.CreateEndpoint(&wq)
	if ipErr != nil {
		slog.Error("error creating endpoint", "err", ipErr)
		r.Complete(true)
		return
	}

	loc := &net.TCPAddr{
		IP:   net.IP(id.LocalAddress.AsSlice()),
		Port: int(id.LocalPort),
	}

	r.Complete(false)
	ep.SocketOptions().SetDelayOption(true)

	conn := gonet.NewTCPConn(&wq, ep)

	listen, err := wg.getListenerForAddr(loc)
	if err != nil {
		slog.Error("error handling tcp conn", "err", err)
		conn.Close()
		return
	}

	listen.conns <- conn
}

func (wg *Wireguard) setupForwarding() error {
	stack := wg.stack.Stack()

	// Maybe needed due to https://github.com/google/gvisor/issues/3876
	// seems to break the networking with it enabled though.
	if err := stack.SetPromiscuousMode(1, true); err != nil {
		return fmt.Errorf("failed to set promiscuous mode: %s", err)
	}

	// Enable spoofing on the nic so we can get addresses for the internet
	// sites the guest reaches out to.
	if err := stack.SetSpoofing(1, true); err != nil {
		return fmt.Errorf("failed to set spoofing mode: %s", err)
	}

	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 1024
	tcpFwd := tcp.NewForwarder(wg.stack.Stack(), tcpReceiveBufferSize, maxInFlightConnectionAttempts, wg.handleTcp)
	wg.stack.Stack().SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	return nil
}

func NewServer(addr string) (*Wireguard, error) {
	localAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	tun, stack, err := CreateNetTUN([]netip.Addr{localAddr}, []netip.Addr{}, 1420, false)
	if err != nil {
		return nil, err
	}

	dev := device.NewDevice(
		tun,
		conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "wireguard server: "),
	)

	// Generate Server Key Pair
	sk, pk, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	if err := dev.SetPrivateKey(sk); err != nil {
		return nil, err
	}

	if err := dev.Up(); err != nil {
		return nil, err
	}

	wg := &Wireguard{
		dev:       dev,
		stack:     stack,
		publicKey: pk,
		allowed:   []string{"0.0.0.0/0"},
		listeners: make(map[string]*listener),
	}

	if err := wg.setupForwarding(); err != nil {
		return nil, err
	}

	return wg, nil
}

func NewFromConfig(addr string, config string) (*Wireguard, error) {
	localAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	tun, stack, err := CreateNetTUN([]netip.Addr{localAddr}, []netip.Addr{}, 1420, false)
	if err != nil {
		return nil, err
	}

	dev := device.NewDevice(
		tun,
		conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "wireguard client: "),
	)

	if err := dev.IpcSet(config); err != nil {
		return nil, err
	}

	if err := dev.Up(); err != nil {
		return nil, err
	}

	wg := &Wireguard{
		dev:       dev,
		stack:     stack,
		listeners: make(map[string]*listener),
	}

	if err := wg.setupForwarding(); err != nil {
		return nil, err
	}

	return wg, nil
}

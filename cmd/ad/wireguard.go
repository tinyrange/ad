package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/tinyrange/wireguard"
)

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

type WireguardInstance interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ConfigUrl() string
}

type wireguardInstance struct {
	wg         *wireguard.Wireguard
	internalIp string
	configUrl  string
}

// DialContext implements WireguardInstance.
func (w *wireguardInstance) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if w.internalIp != "" {
		host = w.internalIp
	}

	slog.Debug("dialing wireguard", "host", host, "port", port)

	return w.wg.DialContext(ctx, network, net.JoinHostPort(host, port))
}

func (w *wireguardInstance) ConfigUrl() string {
	return w.configUrl
}

var (
	_ WireguardInstance = &wireguardInstance{}
)

type WireguardRouter interface {
	AddEndpoint(handler NetHandler, internalIp string) (WireguardInstance, error)
	AddDevice(name string, handler NetHandler) (inst WireguardInstance, config string, err error)
	RestoreDevice(name string, config string, handler NetHandler) (WireguardInstance, error)

	RegisterMux(mux *http.ServeMux)
}

// A wireguard router that generates wireguard configurations.
type wireguardRouter struct {
	mtx           sync.Mutex
	publicAddress string
	mtu           int
	serverUrl     string
	configSalt    string
	configs       map[string]configEntry
}

type configEntry struct {
	config   string
	hostname string
}

func (r *wireguardRouter) configKeyFromHostname(hostname string) string {
	hash := sha256.New()
	hash.Write([]byte(r.configSalt))
	hash.Write([]byte(hostname))
	return hex.EncodeToString(hash.Sum(nil))
}

func (r *wireguardRouter) AddEndpoint(handler NetHandler, internalIp string) (WireguardInstance, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	slog.Info("adding wireguard endpoint", "instance", handler)

	wg, err := wireguard.NewServer(HOST_IP, r.mtu, handler)
	if err != nil {
		return nil, err
	}

	peerConfig, err := wg.CreatePeer(r.publicAddress)
	if err != nil {
		return nil, err
	}

	configKey := r.configKeyFromHostname(handler.Hostname())

	r.configs[configKey] = configEntry{
		config:   peerConfig,
		hostname: handler.Hostname(),
	}

	return &wireguardInstance{wg: wg, internalIp: internalIp, configUrl: fmt.Sprintf("%s/wireguard/%s", r.serverUrl, configKey)}, nil
}

func (r *wireguardRouter) serveConfig(w http.ResponseWriter, req *http.Request) {
	configKey := req.PathValue("config")

	slog.Debug("serving wireguard config", "config", configKey)

	config, ok := r.configs[configKey]
	if !ok {
		http.Error(w, "config not found", http.StatusNotFound)
		return
	}

	// Set the content type to plain text
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", config.hostname))

	if _, err := w.Write([]byte(config.config)); err != nil {
		slog.Error("failed to write config", "err", err)
	}
}

func (r *wireguardRouter) RegisterMux(mux *http.ServeMux) {
	mux.HandleFunc("GET /wireguard/{config}", r.serveConfig)
}

func (r *wireguardRouter) translateToDeviceConfig(ip string, peerConfig string) (string, error) {
	var (
		privateKey string
		publicKey  string
		endpoint   string
		listenPort string
	)

	for _, line := range strings.Split(peerConfig, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			if line == "" {
				continue
			}
			return "", fmt.Errorf("invalid line: %s", line)
		}

		switch k {
		case "private_key":
			privateKey = v
		case "public_key":
			publicKey = v
		case "endpoint":
			endpoint = v
		case "listen_port":
			listenPort = v
		}
	}

	// convert private and public key from hex to base64
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", err
	}

	privateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)

	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", err
	}

	publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)

	var config string
	if listenPort == "" {
		config = fmt.Sprintf(`[Interface]
Address = %s
PrivateKey = %s
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 10.40.0.0/16
Endpoint = %s
`,
			ip, privateKey, r.mtu, publicKey, endpoint,
		)
	} else {
		config = fmt.Sprintf(`[Interface]
Address = %s
PrivateKey = %s
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 10.40.0.0/16
Endpoint = %s:%s
`,
			ip, privateKey, r.mtu, publicKey, r.publicAddress, listenPort,
		)
	}

	return config, nil
}

func (r *wireguardRouter) AddDevice(name string, handler NetHandler) (inst WireguardInstance, config string, err error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	wg, err := wireguard.NewServer(HOST_IP, r.mtu, handler)
	if err != nil {
		return nil, "", err
	}

	peerConfig, err := wg.CreatePeer(r.publicAddress)
	if err != nil {
		return nil, "", err
	}

	deviceConfig, err := r.translateToDeviceConfig(handler.IpAddress().String(), peerConfig)
	if err != nil {
		return nil, "", err
	}

	configKey := r.configKeyFromHostname(handler.Hostname())
	r.configs[configKey] = configEntry{
		config:   deviceConfig,
		hostname: handler.Hostname(),
	}

	config, err = wg.GetConfig()
	if err != nil {
		return nil, "", err
	}

	inst = &wireguardInstance{wg: wg, configUrl: fmt.Sprintf("%s/wireguard/%s", r.serverUrl, configKey)}

	return
}

func filterConfigToKeys(config string, keys []string) (string, error) {
	var lines []string

	for _, line := range strings.Split(config, "\n") {
		k, _, ok := strings.Cut(line, "=")
		if !ok {
			if line == "" {
				continue
			}
			return "", fmt.Errorf("invalid line: %s", line)
		}

		for _, key := range keys {
			if k == key {
				lines = append(lines, line)
				break
			}
		}
	}

	return strings.Join(lines, "\n"), nil
}

func (r *wireguardRouter) RestoreDevice(name string, config string, handler NetHandler) (WireguardInstance, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	newConfig, err := filterConfigToKeys(config, []string{"private_key", "public_key", "listen_port", "allowed_ip", "protocol_version", "allowed_ip"})
	if err != nil {
		return nil, err
	}

	wg, err := wireguard.NewFromConfig(HOST_IP, r.mtu, newConfig, handler)
	if err != nil {
		return nil, err
	}

	deviceConfig, err := r.translateToDeviceConfig(handler.IpAddress().String(), config)
	if err != nil {
		return nil, err
	}

	configKey := r.configKeyFromHostname(handler.Hostname())
	r.configs[configKey] = configEntry{
		config:   deviceConfig,
		hostname: handler.Hostname(),
	}

	return &wireguardInstance{wg: wg, configUrl: fmt.Sprintf("%s/wireguard/%s", r.serverUrl, configKey)}, nil
}

func NewWireguardRouter(publicAddress string, mtu int, serverUrl string) (WireguardRouter, error) {
	salt, err := generateRandomString(8)
	if err != nil {
		return nil, err
	}

	return &wireguardRouter{
		publicAddress: publicAddress,
		mtu:           mtu,
		serverUrl:     serverUrl,
		configs:       make(map[string]configEntry),
		configSalt:    salt,
	}, nil
}

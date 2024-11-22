package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/tinyrange/ad/pkg/common"
	"github.com/tinyrange/wireguard"
)

type wireguardInstance struct {
	wg         *wireguard.Wireguard
	handler    *wireguard.SimpleFlowHandler
	peerConfig string
	isDevice   bool
	deviceId   int
	name       string
}

func (w *wireguardInstance) DeviceIP() string {
	return net.IPv4(10, 40, 30, 1+byte(w.deviceId)).String()
}

func (w *wireguardInstance) addSimpleListener(addr string, cb func(net.Conn)) error {
	listen, err := w.handler.ListenTCPAddr(addr)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := listen.Accept()
			if err != nil {
				slog.Error("failed to accept connection", "err", err)
				continue
			}

			go cb(conn)
		}
	}()

	return nil
}

type DeviceConfig struct {
	ConfigKey string
	Config    string
	ID        int
}

type WireguardDevice struct {
	ConfigKey string
	Config    string
	ID        int
	Name      string
	IP        string
}

// A wireguard router that generates wireguard configurations.
type WireguardRouter struct {
	mtx           sync.Mutex
	publicAddress string
	mtu           int
	serverUrl     string
	endpoints     map[string]*wireguardInstance
}

func (r *WireguardRouter) getInstance(instanceId string) (*wireguardInstance, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	instance, ok := r.endpoints[instanceId]
	if !ok {
		return nil, fmt.Errorf("instance not found")
	}

	return instance, nil
}

func (r *WireguardRouter) AddListener(instanceId, addr string) (net.Listener, error) {
	instance, err := r.getInstance(instanceId)
	if err != nil {
		return nil, err
	}

	return instance.handler.ListenTCPAddr(addr)
}

func (r *WireguardRouter) AddSimpleListener(instanceId, addr string, cb func(net.Conn)) error {
	instance, err := r.getInstance(instanceId)
	if err != nil {
		return err
	}

	return instance.addSimpleListener(addr, cb)
}

func (r *WireguardRouter) AddSimpleForwarder(source string, sourceAddr string, dest string, destAddr string) error {
	sourceInstance, err := r.getInstance(source)
	if err != nil {
		return err
	}

	listen, err := sourceInstance.handler.ListenTCPAddr(sourceAddr)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := listen.Accept()
			if err != nil {
				slog.Error("failed to accept connection", "err", err)
				continue
			}

			go func() {
				destInstance, err := r.getInstance(dest)
				if err != nil {
					slog.Error("failed to get dest instance", "err", err)
					return
				}

				otherConn, err := destInstance.wg.Dial("tcp", destAddr)
				if err != nil {
					slog.Error("failed to dial", "err", err)
					return
				}

				go common.Proxy(conn, otherConn, 4096)
			}()
		}
	}()

	return nil
}

func (r *WireguardRouter) AddEndpoint(instanceId string) (string, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	slog.Info("adding wireguard endpoint", "instance", instanceId)

	handler := wireguard.NewSimpleFlowHandler()
	wg, err := wireguard.NewServer(HOST_IP, r.mtu, handler)
	if err != nil {
		return "", err
	}

	listen, err := handler.ListenTCPAddr("8.8.8.8:80")
	if err != nil {
		return "", err
	}
	go func() {
		for {
			conn, err := listen.Accept()
			if err != nil {
				slog.Error("failed to accept connection", "err", err)
				continue
			}

			conn.Close()
		}
	}()

	r.endpoints[instanceId] = &wireguardInstance{
		wg:      wg,
		handler: handler,
	}

	peerConfig, err := wg.CreatePeer(r.publicAddress)
	if err != nil {
		return "", err
	}

	r.endpoints[instanceId].peerConfig = peerConfig

	return fmt.Sprintf("%s/wireguard/%s", r.serverUrl, instanceId), nil
}

func (r *WireguardRouter) DialContext(ctx context.Context, instanceId string, network, address string) (net.Conn, error) {
	// slog.Info("dialing", "instance", instanceId, "network", network, "address", address)

	instance, err := r.getInstance(instanceId)
	if err != nil {
		return nil, err
	}

	return instance.wg.DialContext(ctx, network, address)
}

func (r *WireguardRouter) serveConfig(w http.ResponseWriter, req *http.Request) {
	instanceId := req.PathValue("instance")

	slog.Debug("serving wireguard config", "instance", instanceId)

	instance, err := r.getInstance(instanceId)
	if err != nil {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	// Set the content type to plain text
	w.Header().Set("Content-Type", "text/plain")

	// Set the file to download and set a filename
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", strings.ReplaceAll(instance.name, "-", "_")))

	if _, err := w.Write([]byte(instance.peerConfig)); err != nil {
		slog.Error("failed to write config", "err", err)
	}
}

func (r *WireguardRouter) registerMux(mux *http.ServeMux) {
	mux.HandleFunc("GET /wireguard/{instance}", r.serveConfig)
}

func (r *WireguardRouter) GetDevices() []WireguardDevice {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	var devices []WireguardDevice

	for instanceId, instance := range r.endpoints {
		if !instance.isDevice {
			continue
		}

		devices = append(devices, WireguardDevice{
			ConfigKey: instanceId,
			Config:    instance.peerConfig,
			ID:        instance.deviceId,
			Name:      instance.name,
			IP:        instance.DeviceIP(),
		})
	}

	return devices
}

func (r *WireguardRouter) translateToDeviceConfig(instance *wireguardInstance, peerConfig string) (string, error) {
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
			instance.DeviceIP(), privateKey, r.mtu, publicKey, endpoint,
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
			instance.DeviceIP(), privateKey, r.mtu, publicKey, r.publicAddress, listenPort,
		)
	}

	return config, nil
}

func (r *WireguardRouter) AddDevice(name string) (instanceId string, config string, id int, err error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	instanceUuid, err := uuid.NewRandom()
	if err != nil {
		return "", "", -1, err
	}

	instanceId = instanceUuid.String()

	id = len(r.endpoints)

	handler := wireguard.NewSimpleFlowHandler()
	wg, err := wireguard.NewServer(HOST_IP, r.mtu, handler)
	if err != nil {
		return "", "", -1, err
	}

	r.endpoints[instanceId] = &wireguardInstance{
		wg:       wg,
		handler:  handler,
		isDevice: true,
		deviceId: id,
		name:     name,
	}

	peerConfig, err := wg.CreatePeer(r.publicAddress)
	if err != nil {
		return "", "", -1, err
	}

	deviceConfig, err := r.translateToDeviceConfig(r.endpoints[instanceId], peerConfig)
	if err != nil {
		return "", "", -1, err
	}

	r.endpoints[instanceId].peerConfig = deviceConfig

	config, err = wg.GetConfig()
	if err != nil {
		return "", "", -1, err
	}

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

func (r *WireguardRouter) restoreDevice(name string, config DeviceConfig) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	newConfig, err := filterConfigToKeys(config.Config, []string{"private_key", "public_key", "listen_port", "allowed_ip", "protocol_version", "allowed_ip"})
	if err != nil {
		return err
	}

	handler := wireguard.NewSimpleFlowHandler()
	wg, err := wireguard.NewFromConfig(HOST_IP, r.mtu, newConfig, handler)
	if err != nil {
		return err
	}

	inst := &wireguardInstance{
		wg:       wg,
		handler:  handler,
		isDevice: true,
		deviceId: config.ID,
		name:     name,
	}

	deviceConfig, err := r.translateToDeviceConfig(inst, config.Config)
	if err != nil {
		return err
	}

	r.endpoints[config.ConfigKey] = inst

	inst.peerConfig = deviceConfig

	return nil
}

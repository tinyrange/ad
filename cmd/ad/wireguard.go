package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/tinyrange/ad/pkg/common"
	"github.com/tinyrange/wireguard"
)

type wireguardInstance struct {
	wg         *wireguard.Wireguard
	peerConfig string
}

func (w *wireguardInstance) addSimpleListener(addr string, cb func(net.Conn)) error {
	listen, err := w.wg.ListenTCPAddr(addr)
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

// A wireguard router that generates wireguard configurations.
type WireguardRouter struct {
	mtx           sync.Mutex
	publicAddress string
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

	return instance.wg.ListenTCPAddr(addr)
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

	listen, err := sourceInstance.wg.ListenTCPAddr(sourceAddr)
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

	wg, err := wireguard.NewServer(HOST_IP)
	if err != nil {
		return "", err
	}

	listen, err := wg.ListenTCPAddr("8.8.8.8:80")
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
		wg: wg,
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

func (r *WireguardRouter) ServeConfig(w http.ResponseWriter, req *http.Request) {
	instanceId := req.PathValue("instance")

	slog.Debug("serving wireguard config", "instance", instanceId)

	instance, err := r.getInstance(instanceId)
	if err != nil {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(instance.peerConfig))
}

func (r *WireguardRouter) registerMux(mux *http.ServeMux) {
	mux.HandleFunc("GET /wireguard/{instance}", r.ServeConfig)
}

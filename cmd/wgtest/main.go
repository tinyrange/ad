package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/tinyrange/ad/pkg/wireguard"
)

const RESP = "Hello, World!"

func appMain() error {
	slog.Info("starting server")
	wg, err := wireguard.NewServer("10.0.0.1", []string{"0.0.0.0/0"})
	if err != nil {
		return fmt.Errorf("failed to create wireguard server: %w", err)
	}

	peer, err := wg.CreatePeer("127.0.0.1")
	if err != nil {
		return fmt.Errorf("failed to create peer config: %w", err)
	}

	// slog.Info("using config", "config", peer)

	slog.Info("starting client")
	wg2, err := wireguard.NewFromConfig("10.0.0.2", peer)
	if err != nil {
		return fmt.Errorf("failed to create wireguard client: %w", err)
	}

	listen, err := wg.ListenTCPAddr("100.54.1.10:http")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		mux := http.NewServeMux()

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(RESP))
		})

		http.Serve(listen, mux)
	}()

	client := http.Client{
		Transport: &http.Transport{
			DialContext: wg2.DialContext,
		},
	}

	slog.Info("dialing")

	resp, err := client.Get("http://100.54.1.10")
	if err != nil {
		return fmt.Errorf("failed to get: %w", err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if string(content) != RESP {
		return fmt.Errorf("unexpected response: %s", content)
	}

	slog.Info("response", "content", string(content))

	return nil
}

func main() {
	if err := appMain(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

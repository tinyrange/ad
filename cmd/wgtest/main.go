package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/tinyrange/ad/pkg/wireguard"
)

func checkResponse(wg *wireguard.Wireguard, url string, expected string) error {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: wg.DialContext,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to get: %w", err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if string(content) != expected {
		return fmt.Errorf("unexpected response: %s", content)
	}

	return nil
}

func appMain() error {
	slog.Info("starting server")
	wg, err := wireguard.NewServer("10.0.0.1")
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

	slog.Info("dialing basic")

	{
		listen, err := wg.ListenTCPAddr("100.54.1.10:http")
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}

		go func() {
			mux := http.NewServeMux()

			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hello, World"))
			})

			http.Serve(listen, mux)
		}()
	}

	if err := checkResponse(wg2, "http://100.54.1.10", "Hello, World"); err != nil {
		return err
	}

	slog.Info("test any ip address")

	{
		listen, err := wg.ListenTCPAddr("0.0.0.0:http")
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}

		go func() {
			mux := http.NewServeMux()

			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hello, World"))
			})

			http.Serve(listen, mux)
		}()
	}

	if err := checkResponse(wg2, "http://30.54.0.10", "Hello, World"); err != nil {
		return err
	}

	slog.Info("other direction")

	{
		listen, err := wg2.ListenTCPAddr("0.0.0.0:0")
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}

		go func() {
			mux := http.NewServeMux()

			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hello, World"))
			})

			http.Serve(listen, mux)
		}()
	}

	if err := checkResponse(wg, "http://30.54.0.10", "Hello, World"); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := appMain(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

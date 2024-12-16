package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

type singleListener struct {
	addr net.Addr
	conn net.Conn
}

// Accept implements net.Listener.
func (s *singleListener) Accept() (net.Conn, error) {
	if s.conn != nil {
		return nil, io.EOF
	}

	c := s.conn
	s.conn = nil
	return c, nil
}

// Addr implements net.Listener.
func (s *singleListener) Addr() net.Addr {
	return s.addr
}

// Close implements net.Listener.
func (s *singleListener) Close() error {
	return nil
}

var (
	_ net.Listener = &singleListener{}
)

type hostService struct {
	name   string
	port   int
	tags   TagList
	accept func(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn)
}

// DialContext implements FlowService.
func (h *hostService) DialContext(ctx context.Context, target FlowInstance) (net.Conn, error) {
	// create an in-memory pipe
	client, server := net.Pipe()
	go h.accept(nil, target, h, server)
	return client, nil
}

// AcceptConn implements FlowService.
func (h *hostService) AcceptConn(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) {
	h.accept(source, target, service, conn)
}

// implements FlowService.
func (h *hostService) Name() string  { return h.name }
func (h *hostService) Port() int     { return h.port }
func (h *hostService) Tags() TagList { return h.tags }

var (
	_ FlowService = &hostService{}
)

func (game *AttackDefenseGame) teamFromFlowInstance(instance FlowInstance) (*Team, bool, error) {
	tags := instance.Tags()

	for _, tag := range tags {
		if strings.HasPrefix(tag, "team/") || strings.HasPrefix(tag, "bot/") || strings.HasPrefix(tag, "device/") {
			return game.teamFromTag(tag)
		}
	}

	return nil, false, fmt.Errorf("no team tag found")
}

func (game *AttackDefenseGame) registerInternalServices() error {
	game.flagSubmission = &hostService{
		name: "flag_submission",
		port: 5000,
		tags: TagList{"public"},
		accept: func(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) {
			defer conn.Close()

			team, bot, err := game.teamFromFlowInstance(source)
			if err != nil {
				slog.Error("failed to get team from source", "src", source, "error", err)
				return
			}

			var info TargetInfo
			if bot {
				info = team.BotInfo()
			} else {
				info = team.Info()
			}

			// read each line from the connection
			scanner := bufio.NewScanner(conn)
			for scanner.Scan() {
				flag := scanner.Text()

				status := game.submitFlag(info, flag)

				if status != FlagAccepted {
					slog.Info("received invalid flag", "team", info.Name, "flag", flag, "status", status)
				}

				fmt.Fprintf(conn, "%s\n", status)
			}
		},
	}
	game.internalWeb = &hostService{
		name: "web",
		port: 80,
		tags: TagList{"public"},
		accept: func(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) {
			team, bot, err := game.teamFromFlowInstance(source)
			if err != nil {
				slog.Error("failed to get team from source", "src", source, "error", err)
				return
			}

			var info TargetInfo
			if bot {
				info = team.BotInfo()
			} else {
				info = team.Info()
			}

			// Create a new server for each connection.
			s := http.Server{
				BaseContext: func(l net.Listener) context.Context {
					return context.WithValue(context.Background(), CONTEXT_KEY_TEAM, info)
				},
				Handler: game.privateServer,
			}

			// Serve only a single connection.
			s.Serve(&singleListener{conn: conn})
		},
	}
	game.pingService = &hostService{
		name: "ping",
		port: 8080,
		tags: TagList{"public"},
		accept: func(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) {
			defer conn.Close()

			slog.Info("ping", "source", source.Hostname(), "target", target.Hostname(), "service", service.Name())

			fmt.Fprintf(conn, "pong\n")
		},
	}

	return nil
}

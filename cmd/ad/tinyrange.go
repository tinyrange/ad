package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type TinyRangeInstance struct {
	game       *AttackDefenseGame
	cmd        *exec.Cmd
	name       string
	instanceId string
}

func (t *TinyRangeInstance) Name() string {
	return t.name
}

func (t *TinyRangeInstance) InstanceId() string {
	return t.instanceId
}

func (t *TinyRangeInstance) Dial(network, address string) (net.Conn, error) {
	return t.DialContext(context.Background(), network, address)
}

func (t *TinyRangeInstance) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return t.game.Router.DialContext(ctx, t.instanceId, network, address)
}

func (t *TinyRangeInstance) Start(templateName string, instanceId string, wireguardConfigUrl string) error {
	// Load the template.
	template, ok := t.game.getCachedTemplate(templateName)
	if !ok {
		return fmt.Errorf("template %s not found", templateName)
	}

	args := []string{
		t.game.TinyRangePath, "run-vm",
		"--wireguard", wireguardConfigUrl,
		"--debug",
	}

	if *verbose {
		args = append(args, "--verbose")
	}

	args = append(args, template)

	// Run `tinyrange run-vm <template>` to start the instance.
	cmd := exec.Command(args[0], args[1:]...)

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tinyrange instance: %w", err)
	}

	t.cmd = cmd
	t.instanceId = instanceId

	return nil
}

func (t *TinyRangeInstance) RunCommand(command string, timeout time.Duration) (string, error) {
	if t.game == nil || t.cmd == nil {
		return "", fmt.Errorf("instance not started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// slog.Info("running command", "instance", t.instanceId, "command", command)

	// Use game.Dial to connect to the instance.
	conn, err := t.game.DialContext(ctx, t.instanceId, "tcp", VM_SSH_IP_PORT)
	if err != nil {
		return "", fmt.Errorf("failed to dial instance: %w", err)
	}
	defer conn.Close()

	// The instance is listening on SSH on port 2222.
	// Use the hardcoded password "insecurepassword" to login.
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, VM_SSH_IP_PORT, &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("insecurepassword"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create ssh client: %w", err)
	}
	defer sshConn.Close()

	client := ssh.NewClient(sshConn, chans, reqs)

	// Create a new session.
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	// Run the command.
	out, err := session.CombinedOutput(command)
	if err != nil && err != io.EOF {
		return string(out), fmt.Errorf("failed to run command: %w", err)
	}

	// slog.Info("command output", "instance", t.instanceId, "output", string(out))

	return string(out), nil
}

type webSocketWriter struct {
	underlyingStream *websocket.Conn
	recorder         io.WriteCloser
}

// Close implements io.WriteCloser.
func (w *webSocketWriter) Close() error {
	if w.recorder != nil {
		return w.recorder.Close()
	}

	return nil
}

// Write implements io.WriteCloser.
func (w *webSocketWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Always try to write to the user first.
	s := base64.StdEncoding.EncodeToString(p)

	err = w.underlyingStream.WriteJSON(&struct {
		Output string `json:"output"`
	}{s})
	if err != nil {
		return -1, err
	}

	// WebSockets are message oriented so short writes are not possible.
	return len(p), nil
}

var (
	_ io.WriteCloser = &webSocketWriter{}
)

func (t *TinyRangeInstance) WebSSHHandler(ws *websocket.Conn) error {
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("insecurepassword"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	var (
		conn  net.Conn
		c     ssh.Conn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
		err   error
	)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		conn, err = t.DialContext(ctx, "tcp", VM_SSH_IP_PORT)
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				slog.Debug("failed to connect", "err", err)
			}
			continue
		}

		c, chans, reqs, err = ssh.NewClientConn(conn, VM_SSH_IP_PORT, config)
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				slog.Debug("failed to connect", "err", err)
			}
			continue
		}

		break
	}

	client := ssh.NewClient(c, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm-256color", 25, 80, ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}); err != nil {
		return fmt.Errorf("failed to request pty: %v", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to pipe stdin: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to pipe stdout: %v", err)
	}
	defer stdin.Close()

	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}

	wsWriter := &webSocketWriter{underlyingStream: ws}
	defer wsWriter.Close()

	go func() {
		for {
			// Pipe output to the websocket
			buf := make([]byte, 1024)

			n, err := stdout.Read(buf)
			if err != nil {
				slog.Warn("failed to read stdout", "error", err)
				break
			}

			_, err = wsWriter.Write(buf[:n])
			if err != nil {
				slog.Warn("failed to write to socket", "error", err)
				break
			}
		}
	}()

	for {
		var inputEv struct {
			Resize bool   `json:"resize"`
			Rows   int    `json:"rows"`
			Cols   int    `json:"cols"`
			Input  string `json:"input"`
		}
		// Get input from the websocket
		err := ws.ReadJSON(&inputEv)
		if err != nil {
			return fmt.Errorf("failed to read json: %v", err)
		}

		if inputEv.Resize {
			err := session.WindowChange(inputEv.Rows, inputEv.Cols)
			if err != nil {
				slog.Warn("failed to resize wsssh window", "error", err)
			}
		} else {
			_, err = stdin.Write([]byte(inputEv.Input))
			if err != nil {
				return fmt.Errorf("failed to write to stdin: %v", err)
			}
		}
	}
}

func (t *TinyRangeInstance) Stop() error {
	if t.cmd == nil {
		return fmt.Errorf("instance not started")
	}

	if runtime.GOOS == "windows" {
		if err := t.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill process: %w", err)
		}
	} else {
		if err := t.cmd.Process.Signal(os.Interrupt); err != nil {
			return fmt.Errorf("failed to send interrupt: %w", err)
		}
	}

	return nil
}

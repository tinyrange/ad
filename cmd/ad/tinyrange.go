package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type SecureSSHConfig struct {
	HostKey   string `json:"ssh_host_key"`
	PublicKey string `json:"ssh_public_key"`
	Password  string `json:"ssh_password"`
}

type TinyRangeInstance interface {
	Name() string
	InstanceId() string
	SecureConfig() (SecureSSHConfig, error)

	Start(templateName string, instanceId string, wireguardConfigUrl string, secureSSHPath string) error
	Stop() error

	RunCommand(ctx context.Context, command string) (string, error)
	WebSSHHandler(ws *websocket.Conn) error
}

type tinyRangeInstance struct {
	mtx             sync.Mutex
	game            *AttackDefenseGame
	cmd             *exec.Cmd
	name            string
	instanceId      string
	secureSSHPath   string
	secureConfig    SecureSSHConfig
	sshClientConfig *ssh.ClientConfig
}

func (t *tinyRangeInstance) SecureConfig() (SecureSSHConfig, error) {
	if _, err := t.clientConfig(); err != nil {
		return SecureSSHConfig{}, err
	}

	return t.secureConfig, nil
}

func (t *tinyRangeInstance) clientConfig() (*ssh.ClientConfig, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	if t.sshClientConfig == nil {
		if t.secureSSHPath == "" {
			return nil, errors.New("secure ssh path not set")
		}

		// Wait for the secure SSH path to be created.
		for {
			if _, err := os.Stat(t.secureSSHPath); err == nil {
				break
			}

			time.Sleep(50 * time.Millisecond)
		}

		// Load the secure SSH config.

		f, err := os.Open(t.secureSSHPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open secure ssh config: %w", err)
		}
		defer f.Close()

		if err := json.NewDecoder(f).Decode(&t.secureConfig); err != nil {
			return nil, fmt.Errorf("failed to decode secure ssh config: %w", err)
		}

		hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.secureConfig.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key: %w", err)
		}

		t.sshClientConfig = &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.Password(t.secureConfig.Password),
			},
			HostKeyCallback: ssh.FixedHostKey(hostKey),
		}

		slog.Info("created ssh client config", "instance", t.instanceId)
	}

	return t.sshClientConfig, nil
}

func (t *tinyRangeInstance) Name() string {
	return t.name
}

func (t *tinyRangeInstance) InstanceId() string {
	return t.instanceId
}

func (t *tinyRangeInstance) Start(templateName string, instanceId string, wireguardConfigUrl string, secureSSHPath string) error {
	// Load the template.
	template, ok := t.game.getCachedTemplate(templateName)
	if !ok {
		return fmt.Errorf("template %s not found", templateName)
	}

	args := []string{
		t.game.TinyRangePath, "run-vm",
		"--wireguard", wireguardConfigUrl,
		"--secure-ssh", secureSSHPath,
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
	t.secureSSHPath = secureSSHPath

	return nil
}

func (t *tinyRangeInstance) RunCommand(ctx context.Context, command string) (string, error) {
	if t.game == nil || t.cmd == nil {
		return "", fmt.Errorf("instance not started")
	}

	// slog.Info("running command", "instance", t.instanceId, "command", command)

	// Use game.Dial to connect to the instance.
	conn, err := t.game.DialContext(ctx, t.instanceId, "tcp", VM_SSH_IP_PORT)
	if err != nil {
		return "", fmt.Errorf("failed to dial instance: %w", err)
	}
	defer conn.Close()

	config, err := t.clientConfig()
	if err != nil {
		return "", fmt.Errorf("failed to get client config: %w", err)
	}

	// The instance is listening on SSH on port 2222.
	// Use the hardcoded password "insecurepassword" to login.
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, VM_SSH_IP_PORT, config)
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

func (t *tinyRangeInstance) WebSSHHandler(ws *websocket.Conn) error {
	config, err := t.clientConfig()
	if err != nil {
		return fmt.Errorf("failed to get client config: %w", err)
	}

	var (
		conn  net.Conn
		c     ssh.Conn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
	)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		conn, err = t.game.DialContext(ctx, t.InstanceId(), "tcp", VM_SSH_IP_PORT)
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

func (t *tinyRangeInstance) Stop() error {
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

func NewTinyRangeInstance(game *AttackDefenseGame, name string) TinyRangeInstance {
	return &tinyRangeInstance{
		game: game,
		name: name,
	}
}

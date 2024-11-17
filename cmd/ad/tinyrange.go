package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/crypto/ssh"
)

type TinyRangeInstance struct {
	game       *AttackDefenseGame
	cmd        *exec.Cmd
	instanceId string
}

func (t *TinyRangeInstance) Dial(network, address string) (net.Conn, error) {
	return t.game.Router.DialContext(context.Background(), t.instanceId, network, address)
}

func (t *TinyRangeInstance) Start(templateName string, instanceId string, wireguardConfigUrl string) error {
	// Load the template.
	template, ok := t.game.getCachedTemplate(templateName)
	if !ok {
		return fmt.Errorf("template %s not found", templateName)
	}

	args := []string{
		t.game.Config.TinyRange.Path, "run-vm",
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

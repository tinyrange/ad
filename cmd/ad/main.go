package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/tinyrange/ad/pkg/common"
	"github.com/tinyrange/wireguard"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const CURRENT_CONFIG_VERSION = 1

const BOT_ID_OFFSET = 0xffff

const (
	HOST_IP = "10.40.0.1"
	VM_IP   = "10.42.0.2"
)

func ipPort(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

var (
	INTERNAL_WEB_IP_PORT    = ipPort(HOST_IP, 80)
	FLAG_SUBMISSION_IP_PORT = ipPort(HOST_IP, 5000)
	VM_SSH_IP_PORT          = ipPort(VM_IP, 2222)
)

type CONTEXT_KEY string

var (
	CONTEXT_KEY_TEAM = CONTEXT_KEY("team")
)

func GetInfo(ctx context.Context) *TargetInfo {
	t, ok := ctx.Value(CONTEXT_KEY_TEAM).(TargetInfo)
	if !ok {
		return nil
	}

	return &t
}

type Duration struct {
	time.Duration
}

func (dur *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string

	if err := value.Decode(&s); err != nil {
		return err
	}

	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}

	dur.Duration = duration

	return nil
}

var (
	_ yaml.Unmarshaler = &Duration{}
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

type TinyRangeConfig struct {
	Path string `yaml:"path"`
}

type FrontendConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

func (f *FrontendConfig) Url() string {
	return fmt.Sprintf("http://%s:%d", f.Address, f.Port)
}

type ServiceConfig struct {
	Port int `yaml:"port"`
}

type VulnboxConfig struct {
	Template     string                   `yaml:"template"`
	InitTemplate string                   `yaml:"init"`
	Services     map[string]ServiceConfig `yaml:"services"`
}

type EventDefinition struct {
	Command string `yaml:"command"`
}

type EventMap map[string]EventDefinition

type BotConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Template string   `yaml:"template"`
	Events   EventMap `yaml:"events"`
}

func (b *BotConfig) Start() (*TinyRangeInstance, error) {
	return nil, fmt.Errorf("BotConfig.Start not implemented")
}

type ScoreBotConfig struct {
	Template    string `yaml:"template"`
	Command     string `yaml:"command"`
	HealthCheck string `yaml:"health_check"`

	instance *TinyRangeInstance
	mtx      sync.Mutex
	tpl      *template.Template
}

func (v *ScoreBotConfig) getTemplate() (*template.Template, error) {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.tpl == nil {
		tpl, err := template.New("command").Parse(v.Command)
		if err != nil {
			return nil, err
		}

		v.tpl = tpl
	}

	return v.tpl, nil
}

func (v *ScoreBotConfig) Stop() error {
	if v.instance != nil {
		if err := v.instance.Stop(); err != nil {
			return err
		}
	}

	return nil
}

func (v *ScoreBotConfig) Start(game *AttackDefenseGame) error {
	inst, err := game.startInstanceFromTemplate("scorebot", v.Template)
	if err != nil {
		return err
	}

	v.instance = inst

	return nil
}

func (v *ScoreBotConfig) Wait() error {
	for {
		resp, err := v.instance.RunCommand(v.HealthCheck, 1*time.Second)
		if err == nil && resp == "healthy" {
			slog.Info("scorebot healthy")
			return nil
		}

		if err != nil {
			slog.Error("failed to run health check", "err", err)
		} else if resp != "healthy" {
			slog.Error("scorebot not healthy", "resp", resp)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

type scoreBotResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (sb *ScoreBotConfig) Run(game *AttackDefenseGame, info TargetInfo, flag string) (bool, string, error) {
	tpl, err := sb.getTemplate()
	if err != nil {
		return false, "", err
	}

	var buf strings.Builder

	if err := tpl.Execute(&buf, &struct {
		TeamIP  string
		NewFlag string
	}{
		TeamIP:  info.IP,
		NewFlag: flag,
	}); err != nil {
		return false, "", err
	}

	resp, err := sb.instance.RunCommand(buf.String(), 5*time.Second)
	if err != nil {
		// This is considered a internal error.
		return false, "", err
	}

	var response scoreBotResponse

	if err := json.Unmarshal([]byte(resp), &response); err != nil {
		return false, "", err
	}

	return response.Status == "success", response.Message, nil
}

type TimelineEvent struct {
	At    Duration `yaml:"at"`
	Event string   `yaml:"event"`
}

func (tl *TimelineEvent) Tick(game *AttackDefenseGame) int64 {
	return tl.At.Nanoseconds() / game.Config.TickRate.Nanoseconds()
}

func (tl *TimelineEvent) Run(game *AttackDefenseGame) error {
	return game.RunEvent(tl.Event)
}

type Config struct {
	basePath string

	Version       int             `yaml:"version"`
	TinyRange     TinyRangeConfig `yaml:"tinyrange"`
	Frontend      FrontendConfig  `yaml:"frontend"`
	Vulnbox       VulnboxConfig   `yaml:"vulnbox"`
	Bots          BotConfig       `yaml:"bots"`
	ScoreBot      ScoreBotConfig  `yaml:"scorebot"`
	TickRate      Duration        `yaml:"tick_rate"`
	Duration      Duration        `yaml:"duration"`
	FlagValidTime Duration        `yaml:"flag_valid_time"`
	Timeline      []TimelineEvent `yaml:"timeline"`
}

type EventCallback func(game *AttackDefenseGame) error

type Event struct {
	Run EventCallback
}

type TargetInfo struct {
	ID         int
	Name       string
	IP         string
	InstanceId string
	IsBot      bool
}

type Team struct {
	ID          int
	DisplayName string

	teamInstance *TinyRangeInstance
	botInstance  *TinyRangeInstance
}

func (t *Team) Info() TargetInfo {
	return TargetInfo{
		ID:         t.ID,
		Name:       t.DisplayName,
		IP:         t.IP(),
		InstanceId: t.InstanceId(),
		IsBot:      false,
	}
}

func (t *Team) BotInfo() TargetInfo {
	return TargetInfo{
		ID:         BOT_ID_OFFSET + t.ID,
		Name:       t.DisplayName + "_bot",
		IP:         t.BotIP(),
		InstanceId: t.BotInstanceId(),
		IsBot:      true,
	}
}

func (t *Team) submitFlag(bot bool, tickId int, teamId int, serviceId int) error {
	if bot {
		slog.Info("submitting flag", "team", t.DisplayName+"_bot", "tick", tickId, "otherTeam", teamId, "service", serviceId)
	} else {
		slog.Info("submitting flag", "team", t.DisplayName, "tick", tickId, "otherTeam", teamId, "service", serviceId)
	}

	return nil
}

func (t *Team) InstanceId() string {
	if t.teamInstance == nil {
		return ""
	}
	return t.teamInstance.instanceId
}

func (t *Team) BotInstanceId() string {
	if t.botInstance == nil {
		return ""
	}
	return t.botInstance.instanceId
}

func (t *Team) IP() string {
	return net.IPv4(10, 42, 10, 10+byte(t.ID)).String()
}

func (t *Team) BotIP() string {
	return net.IPv4(10, 42, 20, 10+byte(t.ID)).String()
}

func (t *Team) Stop() error {
	if t.teamInstance != nil {
		if err := t.teamInstance.Stop(); err != nil {
			return err
		}
	}

	if t.botInstance != nil {
		if err := t.botInstance.Stop(); err != nil {
			return err
		}
	}

	return nil
}

func (t *Team) runBotCommand(game *AttackDefenseGame, teamInfo TargetInfo, botInfo TargetInfo, command string) error {
	commandTpl, err := template.New("command").Parse(command)
	if err != nil {
		return err
	}

	var buf strings.Builder

	if err := commandTpl.Execute(&buf, &struct {
		TeamIP      string
		TickSeconds float64
	}{
		TeamIP:      teamInfo.IP,
		TickSeconds: game.scaleDuration(game.Config.TickRate.Duration).Seconds(),
	}); err != nil {
		return err
	}

	// Run the command.
	resp, err := t.botInstance.RunCommand(buf.String(), 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to run bot command(%w): %s", err, resp)
	}

	slog.Info("bot command response", "team", botInfo.Name, "response", resp)

	return nil
}

func (t *Team) runInitCommand(game *AttackDefenseGame, target TargetInfo) error {
	initTpl, err := template.New("init").Parse(game.Config.Vulnbox.InitTemplate)
	if err != nil {
		return err
	}

	var buf strings.Builder

	if err := initTpl.Execute(&buf, &struct {
		TeamIP   string
		TeamName string
	}{
		TeamIP:   target.IP,
		TeamName: target.Name,
	}); err != nil {
		return err
	}

	// Run the init command.
	var resp string

	if !target.IsBot {
		resp, err = t.teamInstance.RunCommand(buf.String(), 10*time.Second)
	} else {
		resp, err = t.botInstance.RunCommand(buf.String(), 10*time.Second)
	}
	if err != nil {
		return fmt.Errorf("failed to run init command(%w): %s", err, resp)
	}

	if strings.Trim(resp, " \n") != "success" {
		return fmt.Errorf("init command failed: %s", resp)
	}

	return nil
}

func (t *Team) Start(game *AttackDefenseGame) error {
	// Start the team instance.
	inst, err := game.startInstanceFromTemplate("team_"+t.DisplayName, game.Config.Vulnbox.Template)
	if err != nil {
		return err
	}
	t.teamInstance = inst

	if err := game.registerFlowsForTeam(t, t.Info()); err != nil {
		return err
	}

	// If there is a bot, start the bot instance.
	if game.Config.Bots.Enabled {
		inst, err := game.startInstanceFromTemplate("team_"+t.DisplayName+"_bot", game.Config.Bots.Template)
		if err != nil {
			return err
		}
		t.botInstance = inst

		if err := game.registerFlowsForTeam(t, t.BotInfo()); err != nil {
			return err
		}

		// Open the bot to the team.
		for _, service := range game.Config.Vulnbox.Services {
			if err := game.Router.AddSimpleForwarder(
				t.InstanceId(), ipPort(t.BotIP(), service.Port),
				t.BotInstanceId(), ipPort(VM_IP, service.Port),
			); err != nil {
				return err
			}
		}

		// Open the team to the bot.
		for _, service := range game.Config.Vulnbox.Services {
			if err := game.Router.AddSimpleForwarder(
				t.BotInstanceId(), ipPort(t.IP(), service.Port),
				t.InstanceId(), ipPort(VM_IP, service.Port),
			); err != nil {
				return err
			}
		}
	}

	return nil
}

type AttackDefenseGame struct {
	// Config is the configuration for the game.
	Config Config

	// Signer is the signer for the game.
	Signer *Signer

	// FlagGen is the flag generator for the game.
	FlagGen *FlagGenerator

	// Ticker is a ticker that ticks every tick rate.
	Ticker *time.Ticker

	// CurrentTick is the current tick of the game.
	CurrentTick int64

	// EventQueue is the queue of events to run.
	EventQueue []TimelineEvent

	// Events is a map of events to run.
	Events map[string]*Event

	// Teams is a map of teams in the game.
	Teams []*Team

	// Router is the wireguard router for the game.
	Router *WireguardRouter

	templateMutex sync.Mutex
	// TinyRangeTemplates is a map of tinyrange templates that are already cached.
	// It points to the VM config filename.
	tinyRangeTemplates map[string]string

	// SshServer is the to create for admin connections.
	SshServer string

	// SshServerHostKey is the host key for the SSH server.
	SshServerHostKey string

	// TimeScale is the time scale to run the game at.
	TimeScale float64

	publicServer   *http.Server
	internalServer *http.ServeMux

	rebuildTemplates bool
}

func (game *AttackDefenseGame) ScoreBotInstance() string {
	if game.Config.ScoreBot.instance == nil {
		return ""
	}

	return game.Config.ScoreBot.instance.instanceId
}

func (game *AttackDefenseGame) ResolvePath(path string) string {
	return filepath.Join(game.Config.basePath, path)
}

func (game *AttackDefenseGame) scaleDuration(dur time.Duration) time.Duration {
	return time.Duration(float64(dur.Nanoseconds()) * game.TimeScale)
}

func (game *AttackDefenseGame) registerFlowsForTeam(t *Team, info TargetInfo) error {
	for _, service := range game.Config.Vulnbox.Services {
		// Connect the team machine to itself.
		if err := game.Router.AddSimpleForwarder(
			info.InstanceId, ipPort(info.IP, service.Port),
			info.InstanceId, ipPort(VM_IP, service.Port),
		); err != nil {
			return err
		}
	}

	// Run the init command.
	if err := t.runInitCommand(game, info); err != nil {
		return err
	}

	for _, service := range game.Config.Vulnbox.Services {
		// Connect the scoring machine to the team.
		if err := game.Router.AddSimpleForwarder(
			game.ScoreBotInstance(), ipPort(info.IP, service.Port),
			info.InstanceId, ipPort(VM_IP, service.Port),
		); err != nil {
			return err
		}
	}

	// Connect the flag submission API to the team.
	if err := game.Router.AddSimpleListener(info.InstanceId, FLAG_SUBMISSION_IP_PORT, func(conn net.Conn) {
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
	}); err != nil {
		return err
	}

	internalWeb, err := game.Router.AddListener(info.InstanceId, INTERNAL_WEB_IP_PORT)
	if err != nil {
		return err
	}

	go func() {
		http.Serve(internalWeb, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add the team to the context for r.
			ctx := context.WithValue(r.Context(), CONTEXT_KEY_TEAM, info)

			// Serve the request.
			game.internalServer.ServeHTTP(w, r.WithContext(ctx))
		}))
	}()

	return nil
}

func (game *AttackDefenseGame) getTeam(id int) (*Team, error) {
	if id < 0 || id >= len(game.Teams) {
		return nil, fmt.Errorf("team not found")
	}

	return game.Teams[id], nil
}

type FlagStatus string

const (
	FlagAccepted    FlagStatus = "FLAG_ACCEPTED"
	FlagRejected    FlagStatus = "FLAG_REJECTED"
	FlagExpired     FlagStatus = "FLAG_EXPIRED"
	FlagNotYetValid FlagStatus = "FLAG_NOT_YET_VALID"
	FlagFromOwnTeam FlagStatus = "FLAG_FROM_OWN_TEAM"
	InvalidFlag     FlagStatus = "INVALID_FLAG"
	InvalidService  FlagStatus = "INVALID_SERVICE"
	InvalidTeam     FlagStatus = "INVALID_TEAM"
)

func (game *AttackDefenseGame) submitFlag(info TargetInfo, flag string) FlagStatus {
	tickId, teamId, serviceId, ok := game.FlagGen.Verify(game.Signer.Public(), flag)
	if !ok {
		return InvalidFlag
	}

	if teamId == info.ID {
		return FlagFromOwnTeam
	}

	if serviceId < 0 || serviceId >= len(game.Config.Vulnbox.Services) {
		return InvalidService
	}

	if int64(tickId) < game.CurrentTick-game.FlagValidTicks() {
		return FlagExpired
	}

	if int64(tickId) > game.CurrentTick {
		return FlagNotYetValid
	}

	team, err := game.getTeam(teamId)
	if err != nil {
		return InvalidTeam
	}

	if err := team.submitFlag(info.IsBot, tickId, teamId, serviceId); err != nil {
		return FlagRejected
	}

	return FlagAccepted
}

func (game *AttackDefenseGame) cacheTinyRangeTemplate(templateFilename string) error {
	game.templateMutex.Lock()
	defer game.templateMutex.Unlock()

	resolvedFilename := game.ResolvePath(templateFilename)

	args := []string{
		game.Config.TinyRange.Path, "login",
		"--template",
		"--load-config", resolvedFilename,
	}

	if *verbose {
		args = append(args, "--verbose")
	}

	if game.rebuildTemplates {
		args = append(args, "--rebuild")
	}

	// Run `tinyrange login --template --load-config <templateFilename>` to cache the template.
	cmd := exec.Command(args[0], args[1:]...)

	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to cache tinyrange template: %w", err)
	}

	// get only the last line in out.
	lines := strings.Split(string(out), "\n")
	if len(lines) == 0 {
		return fmt.Errorf("failed to cache tinyrange template: no output")
	}

	last := lines[len(lines)-1]
	if last == "" {
		last = lines[len(lines)-2]
	}

	game.tinyRangeTemplates[templateFilename] = last

	return nil
}

func (game *AttackDefenseGame) getCachedTemplate(templateFilename string) (string, bool) {
	game.templateMutex.Lock()
	defer game.templateMutex.Unlock()

	filename, ok := game.tinyRangeTemplates[templateFilename]
	if !ok {
		return "", false
	}

	return filename, true
}

func (game *AttackDefenseGame) ensureTemplateCached(templateFilename string) error {
	if _, ok := game.getCachedTemplate(templateFilename); !ok {
		if err := game.cacheTinyRangeTemplate(templateFilename); err != nil {
			return err
		}
	}

	return nil
}

func (game *AttackDefenseGame) DialContext(ctx context.Context, instanceId string, network, address string) (net.Conn, error) {
	return game.Router.DialContext(ctx, instanceId, network, address)
}

func (game *AttackDefenseGame) generateWireguardConfig() (string, string, error) {
	instanceUuid, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	instanceId := instanceUuid.String()

	// Generate the wireguard config.
	configUrl, err := game.Router.AddEndpoint(instanceId)
	if err != nil {
		return "", "", err
	}

	return instanceId, configUrl, nil
}

func (game *AttackDefenseGame) startInstanceFromTemplate(name string, templateFilename string) (*TinyRangeInstance, error) {
	// Check if the template is already cached.
	if err := game.ensureTemplateCached(templateFilename); err != nil {
		return nil, err
	}

	// Generate the wireguard config URL.
	instanceId, wireguardConfigUrl, err := game.generateWireguardConfig()
	if err != nil {
		return nil, err
	}

	slog.Info("starting instance", "template", templateFilename, "instance", instanceId, "name", name)

	// Start the instance.
	inst := &TinyRangeInstance{
		game: game,
	}

	if err := inst.Start(templateFilename, instanceId, wireguardConfigUrl); err != nil {
		return nil, err
	}

	return inst, nil
}

// RunEvent runs the event with the given name.
func (game *AttackDefenseGame) RunEvent(name string) error {
	ev, ok := game.Events[name]
	if !ok {
		return fmt.Errorf("event %s not implemented", name)
	}

	return ev.Run(game)
}

// TotalTicks returns the total number of ticks in the game.
func (game *AttackDefenseGame) TotalTicks() int64 {
	return game.Config.Duration.Nanoseconds() / game.Config.TickRate.Nanoseconds()
}

func (game *AttackDefenseGame) FlagValidTicks() int64 {
	return game.Config.FlagValidTime.Nanoseconds() / game.Config.TickRate.Nanoseconds()
}

func (game *AttackDefenseGame) AddTeam(name string) {
	game.Teams = append(game.Teams, &Team{
		ID:          len(game.Teams),
		DisplayName: name,
	})
}

func (game *AttackDefenseGame) AddEvent(name string, run EventCallback) {
	game.Events[name] = &Event{Run: run}
}

// ForAllTeams runs the given function for each team in the game.
func (game *AttackDefenseGame) ForAllTeams(includeBots bool, f func(t *Team, info TargetInfo) error) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(game.Teams))

	for _, team := range game.Teams {
		wg.Add(1)
		go func(team *Team) {
			defer wg.Done()
			if err := f(team, team.Info()); err != nil {
				slog.Error("failed to run function for team", "team id", team.ID, "err", err)
				errChan <- err
			}
		}(team)

		if includeBots && game.Config.Bots.Enabled {
			wg.Add(1)

			go func(team *Team) {
				defer wg.Done()
				if err := f(team, team.BotInfo()); err != nil {
					slog.Error("failed to run function for bot", "team id", team.ID, "err", err)
					errChan <- err
				}
			}(team)
		}
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return fmt.Errorf("failed to run function for all teams")
	}

	return nil
}

func (game *AttackDefenseGame) Tick() error {
	// Increment the current tick.
	game.CurrentTick += 1

	slog.Info("tick", "num", game.CurrentTick)

	start := time.Now()

	// Send the scorebot command to each team.
	if err := game.ForAllTeams(true, func(t *Team, info TargetInfo) error {
		start := time.Now()

		// Delay this randomly during the tick interval.
		totalTickTime := game.scaleDuration(game.Config.TickRate.Duration)

		delay := time.Duration(rand.Intn(int(totalTickTime.Milliseconds())/2)) * time.Millisecond

		time.Sleep(delay)

		newFlag := game.FlagGen.Generate(int(game.CurrentTick), info.ID, 0, game.Signer)

		success, message, err := game.Config.ScoreBot.Run(game, info, newFlag)
		if err != nil {
			return err
		}

		slog.Info("scorebot response", "team", info.Name, "success", success, "message", message, "duration", time.Since(start))

		return nil
	}); err != nil {
		slog.Error("failed to run scorebot for each team", "err", err)
	}

	// Run any events that are scheduled for this tick.
	for _, ev := range game.EventQueue {
		if ev.Tick(game) == game.CurrentTick {
			if err := ev.Run(game); err != nil {
				slog.Error("failed to run event", "name", ev.Event, "err", err)
			}
		}
	}

	dur := time.Since(start)

	if dur > game.Config.TickRate.Duration {
		slog.Warn("tick took too long", "duration", dur)
	}

	return nil
}

func (game *AttackDefenseGame) GenerateKeys() error {
	signer, err := GenerateKey()
	if err != nil {
		return err
	}

	game.Signer = signer

	game.FlagGen = NewFlagGenerator("flag{", "}")

	return nil
}

func (game *AttackDefenseGame) startFrontendServer() error {
	handler := http.NewServeMux()

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Attack/Defense Game")
	})

	// Router is allowed to be public since it uses an API key to lookup a configuration.
	game.Router.registerMux(handler)

	game.publicServer = &http.Server{
		Addr:    game.Config.Frontend.Address,
		Handler: handler,
	}

	listener, err := net.Listen("tcp", game.Config.Frontend.Address+":"+fmt.Sprint(game.Config.Frontend.Port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		if err := game.publicServer.Serve(listener); err != nil {
			slog.Error("failed to start server", "err", err)
		}
	}()

	return nil
}

func (game *AttackDefenseGame) registerInternalServer() error {
	game.internalServer = http.NewServeMux()

	// Add a API endpoint for submitting flags.
	game.internalServer.HandleFunc("POST /api/flag", func(w http.ResponseWriter, r *http.Request) {
		info := GetInfo(r.Context())
		if info == nil {
			http.Error(w, "team not found", http.StatusNotFound)
			return
		}

		flag := r.FormValue("flag")
		if flag == "" {
			http.Error(w, "flag not found", http.StatusBadRequest)

			return
		}

		status := game.submitFlag(*info, flag)

		if status != FlagAccepted {
			slog.Info("received invalid flag", "team", info.Name, "flag", flag, "status", status)
		}

		fmt.Fprintf(w, "%s\n", status)
	})

	// Add an API endpoint for getting a list of team IPs.
	game.internalServer.HandleFunc("GET /api/teams", func(w http.ResponseWriter, r *http.Request) {
		playerTeam := GetInfo(r.Context())
		if playerTeam == nil {
			http.Error(w, "team not found", http.StatusNotFound)
			return
		}

		teams := make([]struct {
			Self        bool   `json:"self"`
			IP          string `json:"ip"`
			DisplayName string `json:"display_name"`
		}, len(game.Teams))

		for i, team := range game.Teams {
			teams[i] = struct {
				Self        bool   `json:"self"`
				IP          string `json:"ip"`
				DisplayName string `json:"display_name"`
			}{
				Self:        team.ID == playerTeam.ID,
				IP:          team.IP(),
				DisplayName: team.DisplayName,
			}
		}

		json.NewEncoder(w).Encode(teams)
	})

	return nil
}

func (game *AttackDefenseGame) instanceFromName(name string) (*TinyRangeInstance, error) {
	if name == "scorebot" {
		return game.Config.ScoreBot.instance, nil
	}

	for _, team := range game.Teams {
		if name == fmt.Sprintf("team_%d", team.ID) {
			return team.teamInstance, nil
		}
	}

	return nil, fmt.Errorf("instance not found")
}

func (game *AttackDefenseGame) startSshServer() error {
	slog.Info("starting ssh server", "addr", game.SshServer)

	listen, err := net.Listen("tcp", game.SshServer)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	config := &ssh.ServerConfig{
		NoClientAuth: true,
		NoClientAuthCallback: func(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
			return nil, nil
		},
	}

	privateBytes, err := os.ReadFile(game.SshServerHostKey)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	config.AddHostKey(private)

	go func() {
		for {
			conn, err := listen.Accept()
			if err != nil {
				slog.Error("failed to accept connection", "err", err)
				return
			}

			slog.Info("accepted connection", "remote", conn.RemoteAddr())

			go func() {
				sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					slog.Error("failed to handshake", "err", err)
					return
				}

				_ = sshConn

				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() == "direct-tcpip" {
						data := newChannel.ExtraData()

						hostnameLen := binary.BigEndian.Uint32(data[:4])
						hostname := string(data[4 : 4+hostnameLen])

						instance, err := game.instanceFromName(hostname)
						if err != nil {
							_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("instance not found: %s", hostname))
							return
						}

						other, err := instance.Dial("tcp", VM_SSH_IP_PORT)
						if err != nil {
							_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("failed to dial instance: %s", err))
							return
						}

						chn, reqs, err := newChannel.Accept()
						if err != nil {
							slog.Error("failed to accept channel", "err", err)
							return
						}
						defer chn.Close()

						go ssh.DiscardRequests(reqs)

						if err := common.Proxy(chn, other, 4096); err != nil {
							slog.Error("failed to proxy", "err", err)
						}
					} else {
						_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType()))
						return
					}
				}
			}()
		}
	}()

	return nil
}

func (game *AttackDefenseGame) Run() error {
	// Ensure we clean up all instances when we're done.
	defer func() {
		for _, team := range game.Teams {
			if err := team.Stop(); err != nil {
				slog.Error("failed to stop team", "err", err)
			}
		}

		if err := game.Config.ScoreBot.Stop(); err != nil {
			slog.Error("failed to stop scorebot", "err", err)
		}
	}()

	// Generate a key using age for the game.
	// This key will be used to sign the flags.
	if err := game.GenerateKeys(); err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	game.Router = &WireguardRouter{
		serverUrl:     game.Config.Frontend.Url(),
		publicAddress: game.Config.Frontend.Address,
		endpoints:     make(map[string]*wireguardInstance),
	}

	// Start the built in web server.
	if err := game.startFrontendServer(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	if err := game.registerInternalServer(); err != nil {
		return fmt.Errorf("failed to register internal server: %w", err)
	}

	if game.SshServer != "" {
		// Start the SSH server.
		if err := game.startSshServer(); err != nil {
			return fmt.Errorf("failed to start ssh server: %w", err)
		}
	}

	// Register events for the game.
	if game.Config.Bots.Enabled {
		for name, ev := range game.Config.Bots.Events {
			game.AddEvent(fmt.Sprintf("bot/%s", name), func(game *AttackDefenseGame) error {
				return game.ForAllTeams(false, func(t *Team, info TargetInfo) error {
					return t.runBotCommand(game, t.Info(), t.BotInfo(), ev.Command)
				})
			})
		}
	}

	// Log the start of the game.
	slog.Info("game starting", "completes", time.Now().Add(game.scaleDuration(game.Config.Duration.Duration)), "totalTicks", game.TotalTicks())

	// Sort the timeline events by tick.
	game.EventQueue = game.Config.Timeline
	slices.SortFunc(game.EventQueue, func(a TimelineEvent, b TimelineEvent) int {
		return int(a.Tick(game) - b.Tick(game))
	})

	// Boot the scorebot.
	if err := game.Config.ScoreBot.Start(game); err != nil {
		return fmt.Errorf("failed to start scorebot: %w", err)
	}

	// Wait for the scorebot to boot.
	if err := game.Config.ScoreBot.Wait(); err != nil {
		return fmt.Errorf("failed to wait for scorebot: %w", err)
	}

	// Initialize all initial teams.
	if err := game.ForAllTeams(false, func(t *Team, info TargetInfo) error {
		return t.Start(game)
	}); err != nil {
		return fmt.Errorf("failed to start all teams: %w", err)
	}

	// Create a new ticker for the game.
	game.Ticker = time.NewTicker(game.scaleDuration(game.Config.TickRate.Duration))

	// Create a new timer for the end of the game.
	endTime := time.NewTimer(game.scaleDuration(game.Config.Duration.Duration))

outer:
	for {
		select {
		case <-game.Ticker.C:
			if err := game.Tick(); err != nil {
				slog.Error("failed to tick", "err", err)
			}
		case <-endTime.C:
			break outer
		}
	}

	slog.Info("game complete")

	return nil
}

type arrayFlags []string

// String is an implementation of the flag.Value interface
func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

// Set is an implementation of the flag.Value interface
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	configFile       = flag.String("config", "", "The config file to start the Attack/Defense server with.")
	debugTeam        arrayFlags
	tinyrangePath    = flag.String("tinyrange", "tinyrange", "The path to the tinyrange binary.")
	verbose          = flag.Bool("verbose", false, "Enable verbose logging.")
	sshServer        = flag.String("ssh-server", "", "The SSH server to listen on.")
	sshServerHostKey = flag.String("ssh-server-host-key", "", "The SSH server host key.")
	cpuprofile       = flag.String("cpuprofile", "", "write cpu profile to file")
	timeScale        = flag.Float64("timescale", 1.0, "The time scale to run the game at.")
	rebuild          = flag.Bool("rebuild", false, "Rebuild the tinyrange templates.")
)

func appMain() error {
	flag.Var(&debugTeam, "debug-team", "Create a team for debugging.")
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			return err
		}

		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if *configFile == "" {
		flag.Usage()
		return fmt.Errorf("no config file specified")
	}

	f, err := os.Open(*configFile)
	if err != nil {
		return err
	}

	var config Config

	config.basePath = filepath.Dir(*configFile)

	if err := yaml.NewDecoder(f).Decode(&config); err != nil {
		return err
	}

	if config.Version != CURRENT_CONFIG_VERSION {
		return fmt.Errorf("mismatched version: %d != %d", config.Version, CURRENT_CONFIG_VERSION)
	}

	if *tinyrangePath != "" {
		config.TinyRange.Path = *tinyrangePath
	}

	game := &AttackDefenseGame{
		Config:             config,
		Events:             make(map[string]*Event),
		tinyRangeTemplates: make(map[string]string),
		SshServer:          *sshServer,
		SshServerHostKey:   *sshServerHostKey,
		TimeScale:          *timeScale,
		rebuildTemplates:   *rebuild,
	}

	for _, team := range debugTeam {
		game.AddTeam(team)
	}

	if err := game.Run(); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := appMain(); err != nil {
		slog.Error("fatal", "err", err)
	}
}

package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/tinyrange/ad/pkg/common"
	"github.com/tinyrange/wireguard"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const CURRENT_CONFIG_VERSION = 1

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

// A wireguard router that generates wireguard configurations.
type WireguardRouter struct {
	publicAddress string
	serverUrl     string
	endpoints     map[string]*wireguardInstance
}

func (r *WireguardRouter) AddEndpoint(instanceId string) (string, error) {
	slog.Info("adding wireguard endpoint", "instance", instanceId)

	wg, err := wireguard.NewServer("10.40.0.1")
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
	slog.Info("dialing", "instance", instanceId, "network", network, "address", address)

	instance, ok := r.endpoints[instanceId]
	if !ok {
		return nil, fmt.Errorf("instance not found")
	}

	return instance.wg.DialContext(ctx, network, address)
}

func (r *WireguardRouter) ServeConfig(w http.ResponseWriter, req *http.Request) {
	instanceId := req.PathValue("instance")

	slog.Debug("serving wireguard config", "instance", instanceId)

	instance, ok := r.endpoints[instanceId]
	if !ok {
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
	template, ok := t.game.tinyRangeTemplates[templateName]
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

	// Use game.Dial to connect to the instance.
	conn, err := t.game.DialContext(ctx, t.instanceId, "tcp", "10.42.0.2:2222")
	if err != nil {
		return "", fmt.Errorf("failed to dial instance: %w", err)
	}
	defer conn.Close()

	// The instance is listening on SSH on port 2222.
	// Use the hardcoded password "insecurepassword" to login.
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "10.42.0.2:2222", &ssh.ClientConfig{
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

	slog.Info("running command", "instance", t.instanceId, "command", command)

	// Run the command.
	out, err := session.CombinedOutput(command)
	if err != nil && err != io.EOF {
		return string(out), fmt.Errorf("failed to run command: %w", err)
	}

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

type VulnboxConfig struct {
	Template     string `yaml:"template"`
	InitTemplate string `yaml:"init"`
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
	tpl      *template.Template
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

func (sb *ScoreBotConfig) Run(game *AttackDefenseGame, team *Team, flag string) error {
	if sb.tpl == nil {
		tpl, err := template.New("command").Parse(sb.Command)
		if err != nil {
			return err
		}

		sb.tpl = tpl
	}

	var buf strings.Builder

	if err := sb.tpl.Execute(&buf, &struct {
		TeamIP  string
		NewFlag string
	}{
		TeamIP:  team.IP(),
		NewFlag: flag,
	}); err != nil {
		return err
	}

	resp, err := sb.instance.RunCommand(buf.String(), 5*time.Second)
	if err != nil {
		return err
	}

	slog.Info("scorebot response", "team", team.DisplayName, "resp", resp)

	return fmt.Errorf("not implemented")
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

	Version   int             `yaml:"version"`
	TinyRange TinyRangeConfig `yaml:"tinyrange"`
	Frontend  FrontendConfig  `yaml:"frontend"`
	Vulnbox   VulnboxConfig   `yaml:"vulnbox"`
	Bots      BotConfig       `yaml:"bots"`
	ScoreBot  ScoreBotConfig  `yaml:"scorebot"`
	TickRate  Duration        `yaml:"tick_rate"`
	Duration  Duration        `yaml:"duration"`
	Timeline  []TimelineEvent `yaml:"timeline"`
}

type EventCallback func(game *AttackDefenseGame) error

type Event struct {
	Run EventCallback
}

type Team struct {
	ID          int
	DisplayName string

	teamInstance *TinyRangeInstance
	botInstance  *TinyRangeInstance
}

func (t *Team) IP() string {
	return net.IPv4(10, 42, 0, 10+byte(t.ID)).String()
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

func (t *Team) runInitCommand(game *AttackDefenseGame) error {
	initTpl, err := template.New("init").Parse(game.Config.Vulnbox.InitTemplate)
	if err != nil {
		return err
	}

	var buf strings.Builder

	if err := initTpl.Execute(&buf, &struct {
		TeamIP   string
		TeamName string
	}{
		TeamIP:   t.IP(),
		TeamName: t.DisplayName,
	}); err != nil {
		return err
	}

	// Run the init command.
	resp, err := t.teamInstance.RunCommand(buf.String(), 10*time.Second)
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

	if err := t.runInitCommand(game); err != nil {
		return err
	}

	// If there is a bot, start the bot instance.
	if game.Config.Bots.Enabled {
		inst, err := game.startInstanceFromTemplate("team_"+t.DisplayName+"_bot", game.Config.Bots.Template)
		if err != nil {
			return err
		}
		t.botInstance = inst
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

	// TinyRangeTemplates is a map of tinyrange templates that are already cached.
	// It points to the VM config filename.
	tinyRangeTemplates map[string]string

	// SshServer is the to create for admin connections.
	SshServer string

	// SshServerHostKey is the host key for the SSH server.
	SshServerHostKey string

	server *http.Server
}

func (game *AttackDefenseGame) ResolvePath(path string) string {
	return filepath.Join(game.Config.basePath, path)
}

func (game *AttackDefenseGame) cacheTinyRangeTemplate(templateFilename string) error {
	resolvedFilename := game.ResolvePath(templateFilename)

	// Run `tinyrange login --template --load-config <templateFilename>` to cache the template.
	cmd := exec.Command(game.Config.TinyRange.Path, "login",
		"--template",
		"--load-config", filepath.Base(resolvedFilename),
	)

	cmd.Dir = filepath.Dir(resolvedFilename)

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
	if _, ok := game.tinyRangeTemplates[templateFilename]; !ok {
		if err := game.cacheTinyRangeTemplate(templateFilename); err != nil {
			return nil, err
		}
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
func (game *AttackDefenseGame) ForAllTeams(f func(t *Team) error) error {
	failed := false

	for name, team := range game.Teams {
		if err := f(team); err != nil {
			slog.Error("failed to run function for team", "name", name, "err", err)
			failed = true
		}
	}

	if failed {
		return fmt.Errorf("failed to run function for all teams")
	}

	return nil
}

func (game *AttackDefenseGame) Tick() error {
	// Increment the current tick.
	game.CurrentTick += 1

	// Send the scorebot command to each team.
	// TODO(joshua): Delay this randomly during the tick interval.
	if err := game.ForAllTeams(func(t *Team) error {
		newFlag := game.FlagGen.Generate(int(game.CurrentTick), t.ID, 0, game.Signer)

		return game.Config.ScoreBot.Run(game, t, newFlag)
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

func (game *AttackDefenseGame) startServer() error {
	handler := http.NewServeMux()

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Attack/Defense Game")
	})

	game.Router.registerMux(handler)

	game.server = &http.Server{
		Addr:    game.Config.Frontend.Address,
		Handler: handler,
	}

	listener, err := net.Listen("tcp", game.Config.Frontend.Address+":"+fmt.Sprint(game.Config.Frontend.Port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		if err := game.server.Serve(listener); err != nil {
			slog.Error("failed to start server", "err", err)
		}
	}()

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

						other, err := instance.Dial("tcp", "10.42.0.2:2222")
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

	// Create a new ticker for the game.
	game.Ticker = time.NewTicker(game.Config.TickRate.Duration)

	// Create a new timer for the end of the game.
	endTime := time.NewTimer(game.Config.Duration.Duration)

	game.Router = &WireguardRouter{
		serverUrl:     game.Config.Frontend.Url(),
		publicAddress: game.Config.Frontend.Address,
		endpoints:     make(map[string]*wireguardInstance),
	}

	// Start the built in web server.
	if err := game.startServer(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	if game.SshServer != "" {
		// Start the SSH server.
		if err := game.startSshServer(); err != nil {
			return fmt.Errorf("failed to start ssh server: %w", err)
		}
	}

	// Log the start of the game.
	slog.Info("game starting", "completes", time.Now().Add(game.Config.Duration.Duration), "totalTicks", game.TotalTicks())

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
	if err := game.ForAllTeams(func(t *Team) error {
		return t.Start(game)
	}); err != nil {
		return fmt.Errorf("failed to start all teams: %w", err)
	}

	// TODO(joshua): Run a test tick to make sure all team machines are up.

outer:
	for {
		select {
		case <-game.Ticker.C:
			slog.Info("tick", "num", game.CurrentTick)

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

var (
	configFile       = flag.String("config", "", "The config file to start the Attack/Defense server with.")
	debugTeam        = flag.String("debug-team", "", "Create a team for debugging.")
	tinyrangePath    = flag.String("tinyrange", "tinyrange", "The path to the tinyrange binary.")
	verbose          = flag.Bool("verbose", false, "Enable verbose logging.")
	sshServer        = flag.String("ssh-server", "", "The SSH server to listen on.")
	sshServerHostKey = flag.String("ssh-server-host-key", "", "The SSH server host key.")
)

func appMain() error {
	flag.Parse()

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
	}

	if *debugTeam != "" {
		game.AddTeam(*debugTeam)
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

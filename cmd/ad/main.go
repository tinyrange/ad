package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
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

// A wireguard router that generates wireguard configurations.
type WireguardRouter struct {
}

func (r *WireguardRouter) AddEndpoint(instanceId string) (string, error) {
	return "", fmt.Errorf("WireguardRouter.AddEndpoint not implemented")
}

func (r *WireguardRouter) Dial(instanceId string, network, address string) (net.Conn, error) {
	return nil, fmt.Errorf("WireguardRouter.Dial not implemented")
}

func (r *WireguardRouter) ServeConfig(w http.ResponseWriter, req *http.Request) {

}

type TinyRangeInstance struct {
	game       *AttackDefenseGame
	cmd        *exec.Cmd
	instanceId string
}

func (t *TinyRangeInstance) Start(templateName string, instanceId string, wireguardConfigUrl string) error {
	// Load the template.
	template, ok := t.game.tinyRangeTemplates[templateName]
	if !ok {
		return fmt.Errorf("template %s not found", templateName)
	}

	// Run `tinyrange run-vm --template <template>` to start the instance.
	cmd := exec.Command(t.game.Config.TinyRange.Path, "run-vm",
		"--wireguard", wireguardConfigUrl,
		template,
	)

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tinyrange instance: %w", err)
	}

	t.cmd = cmd
	t.instanceId = instanceId

	return nil
}

func (t *TinyRangeInstance) RunCommand(command string) (string, error) {
	// Use game.Dial to connect to the instance.
	conn, err := t.game.Dial(t.instanceId, "tcp", "localhost:2222")
	if err != nil {
		return "", fmt.Errorf("failed to dial instance: %w", err)
	}
	defer conn.Close()

	// The instance is listening on SSH on port 2222.
	// Use the hardcoded password "insecurepassword" to login.
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "localhost:2222", &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("insecurepassword"),
		},
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
	if err != nil {
		return "", fmt.Errorf("failed to run command: %w", err)
	}

	return string(out), nil
}

func (t *TinyRangeInstance) Stop() error {
	return fmt.Errorf("TinyRangeInstance.Stop not implemented")
}

type TinyRangeConfig struct {
	Path string `yaml:"path"`
}

type FrontendConfig struct {
	Address string `yaml:"address"`
}

type VulnboxConfig struct {
	Template string `yaml:"template"`
}

func (v *VulnboxConfig) Start() (*TinyRangeInstance, error) {
	return nil, fmt.Errorf("not implemented")
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
	return nil, fmt.Errorf("not implemented")
}

type ScoreBotConfig struct {
	Template string `yaml:"template"`
	Command  string `yaml:"command"`

	instance *TinyRangeInstance
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
	inst, err := game.startInstanceFromTemplate(v.Template)
	if err != nil {
		return err
	}

	v.instance = inst

	return nil
}

func (sb *ScoreBotConfig) Run(game *AttackDefenseGame, team *Team) error {
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

func (t *Team) Start(game *AttackDefenseGame) error {
	// Start the team instance.
	inst, err := game.startInstanceFromTemplate(game.Config.Vulnbox.Template)
	if err != nil {
		return err
	}
	t.teamInstance = inst

	// If there is a bot, start the bot instance.
	if game.Config.Bots.Enabled {
		inst, err := game.startInstanceFromTemplate(game.Config.Bots.Template)
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

	server *http.Server
}

func (game *AttackDefenseGame) ResolvePath(path string) string {
	return filepath.Join(game.Config.basePath, path)
}

func (game *AttackDefenseGame) cacheTinyRangeTemplate(templateFilename string) error {
	templateFilename = game.ResolvePath(templateFilename)

	// Run `tinyrange login --template --load-config <templateFilename>` to cache the template.
	cmd := exec.Command(game.Config.TinyRange.Path, "login",
		"--template",
		"--load-config", filepath.Base(templateFilename),
	)

	cmd.Dir = filepath.Dir(templateFilename)

	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to cache tinyrange template: %w", err)
	}

	outString := strings.Trim(string(out), "\n")

	game.tinyRangeTemplates[templateFilename] = outString

	return nil
}

func (game *AttackDefenseGame) Dial(instanceId string, network, address string) (net.Conn, error) {
	return game.Router.Dial(instanceId, network, address)
}

func (game *AttackDefenseGame) generateWireguardConfig() (string, string, error) {
	instanceUuid, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	instanceId := instanceUuid.String()

	// Generate the wireguard config.
	config, err := game.Router.AddEndpoint(instanceId)
	if err != nil {
		return "", "", err
	}

	return instanceId, config, nil
}

func (game *AttackDefenseGame) startInstanceFromTemplate(templateFilename string) (*TinyRangeInstance, error) {
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
		return game.Config.ScoreBot.Run(game, t)
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

	return nil
}

func (game *AttackDefenseGame) startServer() error {
	handler := http.NewServeMux()

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Attack/Defense Game")
	})

	game.server = &http.Server{
		Addr:    game.Config.Frontend.Address,
		Handler: handler,
	}

	listener, err := net.Listen("tcp", game.Config.Frontend.Address)
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

	game.Router = &WireguardRouter{}

	// Start the built in web server.
	if err := game.startServer(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	// Log the start of the game.
	slog.Info("game starting", "completes", time.Now().Add(game.Config.Duration.Duration), "totalTicks", game.TotalTicks())

	// Sort the timeline events by tick.
	game.EventQueue = game.Config.Timeline
	slices.SortFunc(game.EventQueue, func(a TimelineEvent, b TimelineEvent) int {
		return int(a.Tick(game) - b.Tick(game))
	})

	// Boot the scorebot.
	// TODO(joshua): Wait until the scorebot is started.
	if err := game.Config.ScoreBot.Start(game); err != nil {
		return fmt.Errorf("failed to start scorebot: %w", err)
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
	configFile = flag.String("config", "", "The config file to start the Attack/Defense server with.")
	debugTeam  = flag.String("debug-team", "", "Create a team for debugging.")
)

func appMain() error {
	flag.Parse()

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

	game := &AttackDefenseGame{
		Config:             config,
		Events:             make(map[string]*Event),
		tinyRangeTemplates: make(map[string]string),
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

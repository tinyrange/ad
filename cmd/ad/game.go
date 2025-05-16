package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tinyrange/ad/pkg/common"
	"golang.org/x/crypto/ssh"
)

type FlagInfo struct {
	TeamId int `json:"teamId"`
	TickId int `json:"tickId"`
}

type ServiceState struct {
	Name string `json:"name"`

	// Summary points of the service.
	Points        float64 `json:"points"`
	TickPoints    float64 `json:"tickPoints"`
	AttackPoints  float64 `json:"attackPoints"`
	DefensePoints float64 `json:"defensePoints"`
	UptimePoints  float64 `json:"uptimePoints"`

	// Raw data for the service.

	// A list of teamIds that flags were lost to.
	LostFlags []FlagInfo `json:"lostFlags"`

	// A list of teamIds that flags were stolen from.
	StolenFlags []FlagInfo `json:"stolenFlags"`

	SuccessfulUptimeChecks int `json:"successfulUptimeChecks"`
	FailedUptimeChecks     int `json:"failedUptimeChecks"`
}

type TeamState struct {
	IsBot bool   `json:"isBot"`
	Name  string `json:"name"`

	// Summary points of the team.
	Points   float64 `json:"points"`
	Position int     `json:"position"`

	// Raw data for the team.
	Services map[int]*ServiceState `json:"services"`
}

func (t *TeamState) GetService(id int) *ServiceState { return t.Services[id] }

type ScoreboardState struct {
	Tick  int64              `json:"tick"`
	Teams map[int]*TeamState `json:"teams"`
}

func (s *ScoreboardState) GetTeam(id int) *TeamState { return s.Teams[id] }

type AttackDefenseGame struct {
	// Persist is the database for the game to persist state.
	Persist *PersistDatabase

	// Config is the configuration for the game.
	Config Config

	// TinyRangePath is the path to the tinyrange binary.
	TinyRangePath string

	// TinyRangeVMMPath is the path to the tinyrange driver binary.
	TinyRangeVMMPath string

	// IP is the IP that the game listens on.
	ListenIP string

	// ExternalIP is the IP that contestants will use to join the game. May differ from ListenIP if using a proxy to expose the game to the internet etc.
	ExternalIP string

	// PublicPort is the port used for the frontend of the game.
	PublicPort int

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
	Router WireguardRouter

	// Flow is the flow router for the game.
	Flow *FlowRouter

	// RouterMTU is the MTU(Maximum Transmission Unit) for the router.
	RouterMTU int

	templateMutex sync.Mutex
	// TinyRangeTemplates is a map of tinyrange templates that are already cached.
	// It points to the VM config filename.
	tinyRangeTemplates map[string]string

	// instances is a list of TinyRange instances.
	instances []TinyRangeInstance

	// devices is a list of external devices in the game.
	devices []*Device

	// SshServer is the SSH server used for admin connections.
	SshServer string

	// SshServerHostKey is the host key for the SSH server.
	SshServerHostKey string

	// TimeScale is the time scale to run the game at.
	TimeScale float64

	scoreboardMtx sync.RWMutex
	Running       atomic.Bool
	CurrentState  *ScoreboardState
	Ticks         []*ScoreboardState
	OverallState  *ScoreboardState

	publicServer  *http.Server
	privateServer *http.ServeMux

	rebuildTemplates bool

	// internal services
	internalWeb    *hostService
	pingService    *hostService
	flagSubmission *hostService
}

// Flows implements FlowInstance.
func (game *AttackDefenseGame) Flows() []ParsedFlow {
	// The host doesn't use flows to make connections.
	return nil
}

// Hostname implements FlowInstance.
func (game *AttackDefenseGame) Hostname() string {
	return "host"
}

// InstanceAddress implements FlowInstance.
func (game *AttackDefenseGame) InstanceAddress() net.IP {
	return net.ParseIP(HOST_IP)
}

// Services implements FlowInstance.
func (game *AttackDefenseGame) Services() []FlowService {
	return []FlowService{
		game.internalWeb,
		game.pingService,
		game.flagSubmission,
	}
}

// Tags implements FlowInstance.
func (game *AttackDefenseGame) Tags() TagList {
	return TagList{"public/host"}
}

func (game *AttackDefenseGame) FrontendUrl() string {
	return fmt.Sprintf("http://%s:%d", game.ListenIP, game.PublicPort)
}

func (game *AttackDefenseGame) ResolvePath(path string) string {
	return filepath.Join(game.Config.basePath, path)
}

func (game *AttackDefenseGame) getInstances() []TinyRangeInstance {
	return game.instances
}

func (game *AttackDefenseGame) GetEvents() []string {
	events := make([]string, 0, len(game.Events))

	for name := range game.Events {
		events = append(events, name)
	}

	return events
}

func (game *AttackDefenseGame) scaleDuration(dur time.Duration) time.Duration {
	return time.Duration(float64(dur.Nanoseconds()) * game.TimeScale)
}

func (game *AttackDefenseGame) teamFromTag(tag string) (team *Team, bot bool, err error) {
	if strings.HasPrefix(tag, "team/") {
		tag = strings.TrimPrefix(tag, "team/")
	} else if strings.HasPrefix(tag, "bot/") {
		tag = strings.TrimPrefix(tag, "bot/")
		bot = true
	} else if strings.HasPrefix(tag, "device/") {
		tag = strings.TrimPrefix(tag, "device/")
	} else {
		return nil, false, fmt.Errorf("invalid tag: %s", tag)
	}

	for _, t := range game.Teams {
		if t.DisplayName == tag {
			return t, bot, nil
		}
	}

	return nil, false, fmt.Errorf("team not found: %s", tag)
}

func (game *AttackDefenseGame) flagsStolenBy(info TargetInfo, serviceId int) []FlagInfo {
	return append(
		game.OverallState.Teams[info.ID].Services[serviceId].StolenFlags,
		game.CurrentState.Teams[info.ID].Services[serviceId].StolenFlags...,
	)
}

func (game *AttackDefenseGame) submitFlag(info TargetInfo, flag string) FlagStatus {
	if !game.Running.Load() {
		return GameNotRunning
	}

	// Locking the mutex now ensures the flag is counted for the current tick.
	// It also ensures that the flag is not counted twice.
	// And it means if a new tick if about to start the flag will be counted for the current tick.
	game.scoreboardMtx.Lock()
	defer game.scoreboardMtx.Unlock()

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

	if int64(tickId) < game.CurrentState.Tick-game.FlagValidTicks() {
		return FlagExpired
	}

	if int64(tickId) > game.CurrentState.Tick {
		return FlagNotYetValid
	}

	// Check if the flag has already been stolen.
	for _, stolen := range game.flagsStolenBy(info, serviceId) {
		if stolen.TeamId == teamId && stolen.TickId == tickId {
			return FlagAlreadyStolen
		}
	}

	slog.Info("flag accepted", "team", info.Name, "target", teamId, "service", serviceId, "tick", tickId)

	ownService := game.CurrentState.Teams[info.ID].Services[serviceId]
	ownService.StolenFlags = append(ownService.StolenFlags, FlagInfo{TeamId: teamId, TickId: tickId})

	otherService := game.CurrentState.Teams[teamId].Services[serviceId]

	otherService.LostFlags = append(otherService.LostFlags, FlagInfo{TeamId: info.ID, TickId: tickId})

	return FlagAccepted
}

func (game *AttackDefenseGame) cacheTinyRangeTemplate(templateFilename string, ram string) error {
	game.templateMutex.Lock()
	defer game.templateMutex.Unlock()

	resolvedFilename := game.ResolvePath(templateFilename)

	args := []string{
		game.TinyRangePath, "login",
		"--template",
		"--load-config", resolvedFilename,
		"--storage", "4096",
	}

	if ram != "" {
		args = append(args, "--ram", ram)
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

func (game *AttackDefenseGame) ensureTemplateCached(templateFilename string, ram string) error {
	if _, ok := game.getCachedTemplate(templateFilename); !ok {
		if err := game.cacheTinyRangeTemplate(templateFilename, ram); err != nil {
			return err
		}
	}

	return nil
}

func (game *AttackDefenseGame) StartInstanceFromConfig(name string, ip string, config InstanceConfig) (TinyRangeInstance, error) {
	// Check if the template is already cached.
	if err := game.ensureTemplateCached(config.Template, config.Ram); err != nil {
		return nil, err
	}

	// Start the instance.
	inst := NewTinyRangeInstance(game, name, net.ParseIP(ip), config)

	slog.Info("starting instance", "template", config.Template, "instance", inst, "name", name)

	game.instances = append(game.instances, inst)

	handler, err := game.Flow.AddInstance(inst)
	if err != nil {
		return nil, err
	}

	wg, err := game.Router.AddEndpoint(handler, VM_IP)
	if err != nil {
		return nil, err
	}

	secureSSHPath, err := game.Persist.EnsurePath("ssh", name)
	if err != nil {
		return nil, err
	}

	if err := inst.Start(config.Template, wg, secureSSHPath); err != nil {
		return nil, err
	}

	return inst, nil
}

// RunEvent runs the event with the given name.
func (game *AttackDefenseGame) RunEvent(ctx context.Context, name string) error {
	ev, ok := game.Events[name]
	if !ok {
		return fmt.Errorf("event %s not implemented", name)
	}

	return ev.Run(ctx, game)
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

func (game *AttackDefenseGame) RemoveEvent(name string) {
	delete(game.Events, name)
}

// ForAllTeams runs the given function for each team in the game.
func (game *AttackDefenseGame) ForAllTeams(includeBots bool, background bool, f func(t *Team, info TargetInfo) error) error {
	if background {
		for _, team := range game.Teams {
			go func(team *Team) {
				if err := f(team, team.Info()); err != nil {
					slog.Error("failed to run function for team", "team id", team.ID, "err", err)
				}
			}(team)
		}

		if includeBots && game.Config.Vulnbox.Bot.Enabled {
			for _, team := range game.Teams {
				go func(team *Team) {
					if err := f(team, team.BotInfo()); err != nil {
						slog.Error("failed to run function for bot", "team id", team.ID, "err", err)
					}
				}(team)
			}
		}

		return nil
	} else {
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

			if includeBots && game.Config.Vulnbox.Bot.Enabled {
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
}

func (game *AttackDefenseGame) setServiceOverallScore(service *ServiceState) {
	totalTicks := float64(service.SuccessfulUptimeChecks + service.FailedUptimeChecks)

	// Calculate the tick points for the service.
	service.TickPoints = totalTicks * game.Config.Scoring.PointsPerTick

	// Calculate the attack points for the service.
	service.AttackPoints = float64(len(service.StolenFlags)) * game.Config.Scoring.PointsPerStolenFlag

	// Calculate the defense points for the service.
	service.DefensePoints = float64(len(service.LostFlags)) * game.Config.Scoring.PointsPerLostFlag

	// Calculate the uptime points for the service.
	service.UptimePoints = float64(service.SuccessfulUptimeChecks) / totalTicks

	// Calculate the overall score for the service.
	service.Points = (service.TickPoints + service.AttackPoints + service.DefensePoints) * service.UptimePoints
}

func (game *AttackDefenseGame) setTeamOverallScore(team *TeamState) {
	score := 0.0

	for i, service := range team.Services {
		game.setServiceOverallScore(service)

		if !game.Config.Vulnbox.Services[i].Private {
			score += service.Points
		}
	}

	team.Points = score
}

func (game *AttackDefenseGame) summarizeState(ticks []*ScoreboardState) *ScoreboardState {
	result := &ScoreboardState{
		Tick:  0,
		Teams: make(map[int]*TeamState),
	}

	// Sum up the overall raw data from each tick.
	for _, tick := range ticks {
		for teamId, team := range tick.Teams {
			teamState, ok := result.Teams[teamId]
			if !ok {
				teamState = &TeamState{
					IsBot: team.IsBot,
					Name:  team.Name,
				}

				teamState.Services = make(map[int]*ServiceState)

				result.Teams[teamId] = teamState
			}

			for i, service := range team.Services {
				serviceState, ok := teamState.Services[i]
				if !ok {
					serviceState = &ServiceState{
						Name: service.Name,
					}

					teamState.Services[i] = serviceState
				}

				// Add the raw data from the service.
				serviceState.LostFlags = append(serviceState.LostFlags, service.LostFlags...)
				serviceState.StolenFlags = append(serviceState.StolenFlags, service.StolenFlags...)
				serviceState.SuccessfulUptimeChecks += service.SuccessfulUptimeChecks
				serviceState.FailedUptimeChecks += service.FailedUptimeChecks
			}
		}

		if tick.Tick > result.Tick {
			result.Tick = tick.Tick
		}
	}

	// Set the overall scores and collect the teams.
	teamPositions := make([]*TeamState, 0, len(result.Teams))

	for _, team := range result.Teams {
		game.setTeamOverallScore(team)

		teamPositions = append(teamPositions, team)
	}

	// Sort the teams by score.
	slices.SortFunc(teamPositions, func(a, b *TeamState) int {
		return int(b.Points) - int(a.Points)
	})

	// Set the positions.
	for i, team := range teamPositions {
		team.Position = i + 1
	}

	return result
}

func (game *AttackDefenseGame) updateScoreboard() error {
	game.scoreboardMtx.Lock()
	defer game.scoreboardMtx.Unlock()

	// Compute the overall state.
	if game.CurrentState != nil {
		game.CurrentState = game.summarizeState([]*ScoreboardState{game.CurrentState})

		game.Ticks = append(game.Ticks, game.CurrentState)

		game.OverallState = game.summarizeState(game.Ticks)
	}

	// Reset the current scoreboard state.
	game.CurrentState = &ScoreboardState{
		Tick:  game.CurrentTick,
		Teams: make(map[int]*TeamState),
	}

	// Populate the new state with the teams.
	for _, team := range game.Teams {
		teamState := &TeamState{
			IsBot: false,
			Name:  team.DisplayName,
		}

		// Populate the services for the team.
		teamState.Services = make(map[int]*ServiceState)
		for i, service := range game.Config.Vulnbox.Services {
			teamState.Services[i] = &ServiceState{
				Name: service.Name(),
			}
		}

		// Add the team to the current state.
		game.CurrentState.Teams[team.ID] = teamState

		if game.Config.Vulnbox.Bot.Enabled {
			// Add the bot to the current state.
			botState := &TeamState{
				IsBot: true,
				Name:  team.DisplayName + "_bot",
			}

			// Populate the services for the bot.
			botState.Services = make(map[int]*ServiceState)
			for i, service := range game.Config.Vulnbox.Services {
				botState.Services[i] = &ServiceState{
					Name: service.Name(),
				}
			}

			// Add the bot to the current state.
			game.CurrentState.Teams[team.BotId()] = botState
		}
	}

	return nil
}

func (game *AttackDefenseGame) Tick() error {
	if game.CurrentTick >= game.TotalTicks() {
		return nil
	}

	// Increment the current tick.
	game.CurrentTick += 1

	slog.Info("tick", "num", game.CurrentTick)

	ctx, cancel := context.WithTimeout(context.Background(), game.scaleDuration(game.Config.TickRate.Duration))
	defer cancel()

	start := time.Now()

	if err := game.updateScoreboard(); err != nil {
		slog.Error("failed to update scoreboard", "err", err)
		return err
	}

	// Run any events that are scheduled for this tick at the start of the tick.
	for _, ev := range game.EventQueue {
		if ev.Tick(game) == game.CurrentTick {
			if err := ev.Run(ctx, game); err != nil {
				slog.Error("failed to run event", "name", ev.Event, "err", err)
			}
		}
	}

	// Send the scorebot command to each team.
	if err := game.ForAllTeams(true, false, func(t *Team, info TargetInfo) error {
		start := time.Now()

		// Run the scorebot for each service.
		if err := game.Config.ScoreBot.ForEachService(func(service *ScoreBotServiceConfig) error {
			// Delay this randomly during the tick interval.
			totalTickTime := game.scaleDuration(game.Config.TickRate.Duration)

			delay := time.Duration(rand.Intn(int(totalTickTime.Milliseconds())/2)) * time.Millisecond

			time.Sleep(delay)

			subCtx, cancel := context.WithTimeout(ctx, game.scaleDuration(service.Timeout.Duration))
			defer cancel()

			tickId := int(game.CurrentTick)
			newFlag := game.FlagGen.Generate(tickId, info.ID, service.Id, game.Signer)

			success, message, err := service.Run(subCtx, &game.Config.ScoreBot, game, info, newFlag)
			if err != nil {
				slog.Error("failed to run scorebot", "err", err)
				success = false
			}

			slog.Info("scorebot response",
				"team", info.Name,
				"service", service.Id,
				"success", success,
				"message", message,
				"duration", time.Since(start),
			)

			// Update the service state.
			if success {
				serviceState := game.CurrentState.Teams[info.ID].Services[service.Id]
				serviceState.SuccessfulUptimeChecks += 1
			} else {
				serviceState := game.CurrentState.Teams[info.ID].Services[service.Id]
				serviceState.FailedUptimeChecks += 1
			}

			return nil
		}); err != nil {
			return err
		}

		return nil
	}); err != nil {
		slog.Error("failed to run scorebot for each team", "err", err)
	}

	dur := time.Since(start)

	if dur > game.scaleDuration(game.Config.TickRate.Duration) {
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

func (game *AttackDefenseGame) instanceFromName(name string) (TinyRangeInstance, error) {
	if name == "scorebot" {
		return game.Config.ScoreBot.instance, nil
	}

	for _, team := range game.Teams {
		if name == team.teamInstance.Hostname() {
			return team.teamInstance, nil
		}
		if team.botInstance != nil && name == team.botInstance.Hostname() {
			return team.botInstance, nil
		}
		if team.socInstance != nil && name == team.socInstance.Hostname() {
			return team.socInstance, nil
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

						other, err := game.DialContext(context.Background(), nil, "tcp", ipPort(instance.Hostname(), VM_SSH_PORT))
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

	var err error

	// Generate a key using age for the game.
	// This key will be used to sign the flags.
	if err := game.GenerateKeys(); err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	if game.RouterMTU == 0 {
		game.RouterMTU = 1420
	}

	game.Router, err = NewWireguardRouter(game.ListenIP, game.ExternalIP, game.RouterMTU, game.FrontendUrl())
	if err != nil {
		return fmt.Errorf("failed to create wireguard router: %w", err)
	}

	game.Flow = NewFlowRouter()

	if _, err := game.Flow.AddInstance(game); err != nil {
		return fmt.Errorf("failed to add host to flow router: %w", err)
	}

	// Start the built in web server.
	if err := game.startPublicServer(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	// Register the routes for the internal server.
	if err := game.registerPrivateServer(); err != nil {
		return fmt.Errorf("failed to register internal server: %w", err)
	}

	// Register the internal services.
	if err := game.registerInternalServices(); err != nil {
		return fmt.Errorf("failed to register internal services: %w", err)
	}

	if game.SshServer != "" {
		// Start the SSH server.
		if err := game.startSshServer(); err != nil {
			return fmt.Errorf("failed to start ssh server: %w", err)
		}
	}

	// Register events for the game.
	if game.Config.Vulnbox.Bot.Enabled {
		for name, ev := range game.Config.Vulnbox.Bot.Events {
			game.AddEvent(fmt.Sprintf("bot/%s", name), func(ctx context.Context, game *AttackDefenseGame) error {
				return game.ForAllTeams(false, ev.Background, func(t *Team, info TargetInfo) error {
					subCtx, cancel := context.WithTimeout(ctx, game.scaleDuration(ev.Timeout.Duration))
					defer cancel()

					return t.runBotCommand(subCtx, game, t.Info(), t.BotInfo(), ev.Command)
				})
			})
		}
	}

	// Sort the timeline events by tick.
	game.EventQueue = game.Config.Timeline
	slices.SortFunc(game.EventQueue, func(a TimelineEvent, b TimelineEvent) int {
		return int(a.Tick(game) - b.Tick(game))
	})

	// Load all existing device configurations.
	if err := game.Persist.ForEach("devices", func(key string, read func(value interface{}) error) error {
		var device DeviceConfig
		if err := read(&device); err != nil {
			return err
		}

		dev, err := game.createDevice(key, device.ID, device.Team)
		if err != nil {
			return fmt.Errorf("failed to add device: %w", err)
		}

		handler, err := game.Flow.AddInstance(dev)
		if err != nil {
			return fmt.Errorf("failed to add device to flow router: %w", err)
		}

		wg, err := game.Router.RestoreDevice(key, device.Config, handler)
		if err != nil {
			return err
		}

		dev.wg = wg
		game.devices = append(game.devices, dev)

		return nil
	}); err != nil {
		return fmt.Errorf("failed to load devices: %w", err)
	}

	// Boot the scorebot.
	if err := game.Config.ScoreBot.Start(game); err != nil {
		return fmt.Errorf("failed to start scorebot: %w", err)
	}

	// Wait for the scorebot to boot.
	if err := game.Config.ScoreBot.Wait(); err != nil {
		return fmt.Errorf("failed to wait for scorebot: %w", err)
	}

	// Initialize all initial teams.
	if err := game.ForAllTeams(false, false, func(t *Team, info TargetInfo) error {
		return t.Start(game)
	}); err != nil {
		return fmt.Errorf("failed to start all teams: %w", err)
	}

	if game.Config.Wait {
		// Wait for a event to start the game.
		slog.Info("waiting for event to start game")

		start := make(chan struct{})

		game.AddEvent("start", func(ctx context.Context, game *AttackDefenseGame) error {
			close(start)
			game.RemoveEvent("start")
			return nil
		})

		<-start
	}

	// Start the game.
	if err := game.Start(); err != nil {
		return fmt.Errorf("failed to start game: %w", err)
	}

	if game.Config.WaitAfter {
		slog.Info("use Ctrl+C to stop the game")

		// Yield forever until the user stops the game.
		<-make(chan struct{})
	}

	return nil
}

func (game *AttackDefenseGame) Start() error {
	// Log the start of the game.
	slog.Info("game starting", "completes", time.Now().Add(game.scaleDuration(game.Config.Duration.Duration)), "totalTicks", game.TotalTicks())

	game.Running.Store(true)

	// Create a new ticker for the game.
	game.Ticker = time.NewTicker(game.scaleDuration(game.Config.TickRate.Duration))

	// Create a new timer for the end of the game.
	// Always add one tick on the end so the game has exactly the right number of ticks.
	endTime := time.NewTimer(game.scaleDuration(game.Config.Duration.Duration) + game.scaleDuration(game.Config.TickRate.Duration))

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

	if err := game.updateScoreboard(); err != nil {
		slog.Error("failed to update scoreboard", "err", err)
	}

	slog.Info("game complete")

	game.Running.Store(false)

	return nil
}

func (game *AttackDefenseGame) createDevice(name string, id int, team string) (*Device, error) {
	if id < 0 {
		id = len(game.devices)
	}

	dev := &Device{
		game: game,
		name: name,
		team: team,
		id:   id,
		ip:   net.IPv4(10, 40, 30, 1+byte(id)).String(),
	}

	if err := dev.ParseTags(); err != nil {
		return nil, fmt.Errorf("failed to parse tags for device (%s): %w", name, err)
	}

	if err := dev.ParseFlows(); err != nil {
		return nil, fmt.Errorf("failed to parse flows for device (%s): %w", name, err)
	}

	return dev, nil
}

func (game *AttackDefenseGame) AddDevice(name string, team string) error {
	if _, err := game.Persist.ValidateKey(name); err != nil {
		return err
	}

	dev, err := game.createDevice(name, len(game.GetDevices()), team)
	if err != nil {
		return err
	}

	handler, err := game.Flow.AddInstance(dev)
	if err != nil {
		return err
	}

	wg, deviceConfig, err := game.Router.AddDevice(name, handler)
	if err != nil {
		return err
	}

	dev.wg = wg
	game.devices = append(game.devices, dev)

	if err := game.Persist.Set("devices", name, &DeviceConfig{
		ID:     dev.id,
		Config: deviceConfig,
		Team:   team,
	}); err != nil {
		return err
	}

	slog.Info("added device", "name", name, "hostname", dev.Hostname())

	return nil
}

func (game *AttackDefenseGame) DialContext(ctx context.Context, source FlowInstance, network, address string) (net.Conn, error) {
	return game.Flow.DialContext(ctx, source, network, address)
}

func (game *AttackDefenseGame) GetDevices() []WireguardDevice {
	devices := make([]WireguardDevice, 0, len(game.devices))

	for _, dev := range game.devices {
		devices = append(devices, WireguardDevice{
			ConfigUrl: dev.wg.ConfigUrl(),
			Name:      dev.name,
			IP:        dev.ip,
		})
	}

	return devices
}

var (
	_ FlowInstance = &AttackDefenseGame{}
)

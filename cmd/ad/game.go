package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
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
	"time"

	"github.com/google/uuid"
	"github.com/tinyrange/ad/pkg/common"
	"golang.org/x/crypto/ssh"
)

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

	// instances is a list of TinyRange instances.
	instances []*TinyRangeInstance

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

func (game *AttackDefenseGame) getInstance(id string) (*TinyRangeInstance, error) {
	for _, inst := range game.instances {
		if inst.InstanceId() == id {
			return inst, nil
		}
	}

	return nil, fmt.Errorf("instance not found")
}

func (game *AttackDefenseGame) getInstances() []*TinyRangeInstance {
	return game.instances
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
		name: name,
	}

	if err := inst.Start(templateFilename, instanceId, wireguardConfigUrl); err != nil {
		return nil, err
	}

	game.instances = append(game.instances, inst)

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

func (game *AttackDefenseGame) RemoveEvent(name string) {
	delete(game.Events, name)
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

	if game.Config.Wait {
		// Wait for a event to start the game.
		slog.Info("waiting for event to start game")

		start := make(chan struct{})

		game.AddEvent("start", func(game *AttackDefenseGame) error {
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

	return nil
}

func (game *AttackDefenseGame) Start() error {
	// Log the start of the game.
	slog.Info("game starting", "completes", time.Now().Add(game.scaleDuration(game.Config.Duration.Duration)), "totalTicks", game.TotalTicks())

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

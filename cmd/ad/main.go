package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strings"

	"gopkg.in/yaml.v3"
)

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
	nopTeam          arrayFlags
	tinyrangePath    = flag.String("tinyrange", "tinyrange", "The path to the tinyrange binary.")
	verbose          = flag.Bool("verbose", false, "Enable verbose logging.")
	sshServer        = flag.String("ssh-server", "", "The SSH server to listen on.")
	sshServerHostKey = flag.String("ssh-server-host-key", "", "The SSH server host key.")
	cpuprofile       = flag.String("cpuprofile", "", "write cpu profile to file")
	timeScale        = flag.Float64("timescale", 1.0, "The time scale to run the game at.")
	rebuild          = flag.Bool("rebuild", false, "Rebuild the tinyrange templates.")
	wait             = flag.Bool("wait", false, "Wait for manual confirmation before starting the game.")
	waitAfter        = flag.Bool("wait-after", false, "Keep services up after the game is complete.")
	publicIp         = flag.String("ip", "127.0.0.1", "The public IP of the server.")
	publicPort       = flag.Int("port", 5100, "The public port of the server.")
	persistancePath  = flag.String("persist-path", "local/persist", "The path to the config file.")
	routerMTU        = flag.Int("router-mtu", 1420, "The MTU of the router.")
)

func appMain() error {
	flag.Var(&nopTeam, "nop-team", "Create a team with no player attached.")
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

	configName := strings.TrimSuffix(filepath.Base(*configFile), filepath.Ext(*configFile))

	persistDir := filepath.Join(*persistancePath, configName)

	slog.Info("persisting to", "dir", persistDir)

	if err := os.MkdirAll(persistDir, 0755); err != nil {
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
		Persist:            NewPersistDatabase(persistDir),
		Config:             config,
		Events:             make(map[string]*Event),
		tinyRangeTemplates: make(map[string]string),
		SshServer:          *sshServer,
		SshServerHostKey:   *sshServerHostKey,
		TimeScale:          *timeScale,
		rebuildTemplates:   *rebuild,
		PublicIP:           *publicIp,
		PublicPort:         *publicPort,
		RouterMTU:          *routerMTU,
	}

	if *tinyrangePath != "" {
		game.TinyRangePath = *tinyrangePath
	} else {
		tinyrange, err := exec.LookPath("tinyrange")
		if err != nil {
			return fmt.Errorf("tinyrange not found in PATH")
		}

		game.TinyRangePath = tinyrange
	}

	if *wait {
		game.Config.Wait = true
	}

	if *waitAfter {
		game.Config.WaitAfter = true
	}

	for _, team := range nopTeam {
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

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/pprof"

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
	opTeam           arrayFlags
	tinyrangePath    = flag.String("tinyrange", "tinyrange", "The path to the tinyrange binary.")
	verbose          = flag.Bool("verbose", false, "Enable verbose logging.")
	sshServer        = flag.String("ssh-server", "", "The SSH server to listen on.")
	sshServerHostKey = flag.String("ssh-server-host-key", "", "The SSH server host key.")
	cpuprofile       = flag.String("cpuprofile", "", "write cpu profile to file")
	timeScale        = flag.Float64("timescale", 1.0, "The time scale to run the game at.")
	rebuild          = flag.Bool("rebuild", false, "Rebuild the tinyrange templates.")
	wait             = flag.Bool("wait", false, "Wait for manual confirmation before starting the game.")
	publicIp         = flag.String("ip", "", "The public IP of the server.")
)

func appMain() error {
	flag.Var(&opTeam, "op-team", "Create a team with no player attached.")
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

	if *wait {
		config.Wait = true
	}

	if *publicIp != "" {
		config.Frontend.Address = *publicIp
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

	for _, team := range opTeam {
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

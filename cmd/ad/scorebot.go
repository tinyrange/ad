package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

type ScoreBotServiceConfig struct {
	Id      int      `yaml:"id"`
	Command string   `yaml:"command"`
	Timeout Duration `yaml:"timeout"`

	mtx sync.Mutex
	tpl *template.Template
}

func (v *ScoreBotServiceConfig) getTemplate() (*template.Template, error) {
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

type scoreBotResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (v *ScoreBotServiceConfig) Run(ctx context.Context, sb *ScoreBotConfig, game *AttackDefenseGame, info TargetInfo, flag string) (bool, string, error) {
	tpl, err := v.getTemplate()
	if err != nil {
		return false, "", err
	}

	var buf strings.Builder

	service := game.Config.Vulnbox.GetService(v.Id)
	if err := tpl.Execute(&buf, &struct {
		TargetIP    string
		FlagId      string
		NewFlag     string
		ServicePort string
	}{
		TargetIP:    info.IP,
		FlagId:      GetFlagId(flag),
		NewFlag:     flag,
		ServicePort: strconv.Itoa(service.Port()),
	}); err != nil {
		return false, "", err
	}

	resp, err := sb.instance.RunCommand(ctx, buf.String())
	if err != nil {
		// This is considered an internal error.
		return false, "", err
	}

	var response scoreBotResponse

	if err := json.Unmarshal([]byte(resp), &response); err != nil {
		return false, "", err
	}

	return response.Status == "success", response.Message, nil
}

type ScoreBotConfig struct {
	InstanceConfig `yaml:",inline"`
	Services       []*ServiceConfig         `yaml:"services"`
	Checks         []*ScoreBotServiceConfig `yaml:"checks"`
	HealthCheck    string                   `yaml:"health_check"`

	instance TinyRangeInstance
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
	inst, err := game.StartInstanceFromConfig("scorebot", SCOREBOT_IP, v.InstanceConfig)
	if err != nil {
		return err
	}

	if err := inst.ParseFlows(func(s string) (string, error) {
		return "", fmt.Errorf("unexpected flow: %s", s)
	}); err != nil {
		return fmt.Errorf("failed to parse flows for scorebot: %w", err)
	}

	for _, service := range v.Services {
		inst.AddService(service)
	}

	v.instance = inst

	return nil
}

func (v *ScoreBotConfig) Wait() error {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		resp, err := v.instance.RunCommand(ctx, v.HealthCheck)
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

func (v *ScoreBotConfig) ForEachService(cb func(*ScoreBotServiceConfig) error) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(v.Services))

	for _, check := range v.Checks {
		wg.Add(1)
		go func(service *ScoreBotServiceConfig) {
			defer wg.Done()
			if err := cb(service); err != nil {
				errChan <- err
			}
		}(check)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return <-errChan
	}

	return nil
}

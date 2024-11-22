package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"text/template"
	"time"
)

type ScoreBotServiceConfig struct {
	Id      int    `yaml:"id"`
	Command string `yaml:"command"`

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

func (v *ScoreBotServiceConfig) Run(sb *ScoreBotConfig, game *AttackDefenseGame, info TargetInfo, flag string) (bool, string, error) {
	tpl, err := v.getTemplate()
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := sb.instance.RunCommand(ctx, buf.String())
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

type ScoreBotConfig struct {
	Template    string                   `yaml:"template"`
	Services    []*ScoreBotServiceConfig `yaml:"services"`
	Tags        TagList                  `yaml:"tags"`
	Flows       FlowList                 `yaml:"flows"`
	HealthCheck string                   `yaml:"health_check"`

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
	inst, err := game.startInstanceFromTemplate("scorebot", v.Template)
	if err != nil {
		return err
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

	for _, service := range v.Services {
		wg.Add(1)
		go func(service *ScoreBotServiceConfig) {
			defer wg.Done()
			if err := cb(service); err != nil {
				errChan <- err
			}
		}(service)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return <-errChan
	}

	return nil
}

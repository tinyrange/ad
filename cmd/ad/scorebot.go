package main

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"text/template"
	"time"
)

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

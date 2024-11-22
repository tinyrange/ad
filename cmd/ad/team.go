package main

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"text/template"
	"time"

	"golang.org/x/net/context"
)

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

	teamInstance TinyRangeInstance
	botInstance  TinyRangeInstance
}

func (t *Team) BotId() int { return BOT_ID_OFFSET + t.ID }

func (t *Team) GetSSHConfig() (SecureSSHConfig, error) {
	if t.teamInstance == nil {
		return SecureSSHConfig{}, fmt.Errorf("team instance not set")
	}

	return t.teamInstance.SecureConfig()
}

func (t *Team) InstanceId() string {
	if t.teamInstance == nil {
		return ""
	}
	return t.teamInstance.InstanceId()
}

func (t *Team) BotInstanceId() string {
	if t.botInstance == nil {
		return ""
	}
	return t.botInstance.InstanceId()
}

func (t *Team) IP() string {
	return net.IPv4(10, 40, 10, 10+byte(t.ID)).String()
}

func (t *Team) BotIP() string {
	return net.IPv4(10, 40, 20, 10+byte(t.ID)).String()
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
		ID:         t.BotId(),
		Name:       t.DisplayName + "_bot",
		IP:         t.BotIP(),
		InstanceId: t.BotInstanceId(),
		IsBot:      true,
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := t.botInstance.RunCommand(ctx, buf.String())
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var resp string

	if !target.IsBot {
		resp, err = t.teamInstance.RunCommand(ctx, buf.String())
	} else {
		resp, err = t.botInstance.RunCommand(ctx, buf.String())
	}
	if err != nil {
		return fmt.Errorf("failed to run init command: %w %s", err, resp)
	}

	if strings.Trim(resp, " \n") != "success" {
		return fmt.Errorf("init command failed: %s", resp)
	}

	return nil
}

func (t *Team) Start(game *AttackDefenseGame) error {
	// Start the team instance.
	inst, err := game.StartInstanceFromConfig("team_"+t.DisplayName, t.IP(), game.Config.Vulnbox.InstanceConfig)
	if err != nil {
		return err
	}
	t.teamInstance = inst

	if err := game.registerFlowsForTeam(t, t.Info()); err != nil {
		return fmt.Errorf("failed to register flows for team (%d): %w", t.ID, err)
	}

	// If there is a bot, start the bot instance.
	if game.Config.Vulnbox.Bot.Enabled {
		inst, err := game.StartInstanceFromConfig("team_"+t.DisplayName+"_bot", t.BotIP(), game.Config.Vulnbox.Bot.InstanceConfig)
		if err != nil {
			return err
		}
		t.botInstance = inst

		if err := game.registerFlowsForTeam(t, t.BotInfo()); err != nil {
			return fmt.Errorf("failed to register flows for team bot (%d): %w", t.ID, err)
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

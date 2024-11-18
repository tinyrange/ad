package main

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

const BOT_ID_OFFSET = 0xffff

const (
	HOST_IP = "10.40.0.1"
	VM_IP   = "10.42.0.2"
)

func ipPort(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

var (
	INTERNAL_WEB_IP_PORT    = ipPort(HOST_IP, 80)
	FLAG_SUBMISSION_IP_PORT = ipPort(HOST_IP, 5000)
	VM_SSH_IP_PORT          = ipPort(VM_IP, 2222)
)

type CONTEXT_KEY string

var (
	CONTEXT_KEY_TEAM = CONTEXT_KEY("team")
)

func GetInfo(ctx context.Context) *TargetInfo {
	t, ok := ctx.Value(CONTEXT_KEY_TEAM).(TargetInfo)
	if !ok {
		return nil
	}

	return &t
}

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

type EventCallback func(game *AttackDefenseGame) error

type Event struct {
	Run EventCallback
}

type FlagStatus string

const (
	GameNotRunning    FlagStatus = "GAME_NOT_RUNNING"
	FlagAccepted      FlagStatus = "FLAG_ACCEPTED"
	FlagAlreadyStolen FlagStatus = "FLAG_ALREADY_STOLEN"
	FlagExpired       FlagStatus = "FLAG_EXPIRED"
	FlagNotYetValid   FlagStatus = "FLAG_NOT_YET_VALID"
	FlagFromOwnTeam   FlagStatus = "FLAG_FROM_OWN_TEAM"
	InvalidFlag       FlagStatus = "INVALID_FLAG"
	InvalidService    FlagStatus = "INVALID_SERVICE"
	InvalidTeam       FlagStatus = "INVALID_TEAM"
)

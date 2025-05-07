package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const BOT_ID_OFFSET = 0xffff
const SOC_ID_OFFSET = 0x1ffff

const (
	HOST_IP     = "10.40.0.1"
	SCOREBOT_IP = "10.40.0.10"

	VM_IP = "10.42.0.2"

	VM_SSH_PORT = 2222
)

func ipPort(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

var (
	INTERNAL_WEB_IP_PORT    = ipPort(HOST_IP, 80)
	FLAG_SUBMISSION_IP_PORT = ipPort(HOST_IP, 5000)
)

type CONTEXT_KEY string

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

type EventCallback func(ctx context.Context, game *AttackDefenseGame) error

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

type TagList []string

func (tags TagList) Contains(tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (tags TagList) ContainsMatchingPrefix(prefix string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

func (tags TagList) ContainsAny(other TagList) bool {
	for _, tag := range other {
		if tags.Contains(tag) {
			return true
		}
	}
	return false
}

func (tags TagList) Parse(rpl ReplaceFunc) (TagList, error) {
	var parsed TagList

	for _, tag := range tags {
		parsedTag, err := ParseTag(tag, rpl)
		if err != nil {
			return nil, err
		}

		parsed = append(parsed, parsedTag)
	}

	return parsed, nil
}

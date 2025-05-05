package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
)

const CURRENT_CONFIG_VERSION = 1

type ServiceConfig struct {
	Id          int     `yaml:"id"`
	ServiceName string  `yaml:"name"`
	ServicePort int     `yaml:"port"`
	ServiceTags TagList `yaml:"tags"`
	Private     bool    `yaml:"private"`
}

// DialContext implements FlowService.
func (s *ServiceConfig) DialContext(ctx context.Context, target FlowInstance) (net.Conn, error) {
	if tr, ok := target.(TinyRangeInstance); ok {
		return tr.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", target.InstanceAddress().String(), s.ServicePort))
	} else {
		slog.Error("invalid target instance", "target", target, "targetType", fmt.Sprintf("%T", target))
		return nil, fmt.Errorf("invalid target instance: %T", target)
	}
}

// AcceptConn implements FlowService.
func (s *ServiceConfig) AcceptConn(source FlowInstance, target FlowInstance, service FlowService, conn net.Conn) {
	if tr, ok := target.(TinyRangeInstance); ok {
		tr.AcceptConn(source, service, conn)
	} else {
		slog.Error("invalid target instance", "target", target, "targetType", fmt.Sprintf("%T", target))
	}
}

// implements FlowService.
func (s *ServiceConfig) Name() string  { return s.ServiceName }
func (s *ServiceConfig) Port() int     { return s.ServicePort }
func (s *ServiceConfig) Tags() TagList { return s.ServiceTags }

var (
	_ FlowService = &ServiceConfig{}
)

type InstanceConfig struct {
	Template string   `yaml:"template"`
	Tags     TagList  `yaml:"tags"`
	Flows    FlowList `yaml:"flows"`
}

type HealthCheckKind string

const (
	HealthCheckKindNone HealthCheckKind = ""
	HealthCheckKindHTTP HealthCheckKind = "http"
)

type HealthCheckConfig struct {
	Kind           HealthCheckKind `yaml:"kind"`
	URL            string          `yaml:"url"`
	ExpectedOutput string          `yaml:"expected"`
}

type VulnboxConfig struct {
	InstanceConfig `yaml:",inline"`
	InitTemplate   string            `yaml:"init"`
	HealthCheck    HealthCheckConfig `yaml:"health_check"`
	Services       []ServiceConfig   `yaml:"services"`
	Bot            BotConfig         `yaml:"bot"`
}

func (v *VulnboxConfig) GetService(id int) *ServiceConfig {
	for _, service := range v.Services {
		if service.Id == id {
			return &service
		}
	}
	return nil
}

func (v *VulnboxConfig) PublicServices() []ServiceConfig {
	publicServices := []ServiceConfig{}
	for _, service := range v.Services {
		if !service.Private {
			publicServices = append(publicServices, service)
		}
	}
	return publicServices
}

type EventDefinition struct {
	Command    string   `yaml:"command"`
	Timeout    Duration `yaml:"timeout"`
	Background bool     `yaml:"background"`
}

type EventMap map[string]EventDefinition

type BotConfig struct {
	InstanceConfig `yaml:",inline"`
	Enabled        bool     `yaml:"enabled"`
	Events         EventMap `yaml:"events"`
}

type DeviceGlobalConfig struct {
	Tags  TagList  `yaml:"tags"`
	Flows FlowList `yaml:"flows"`
}

type ScoringConfig struct {
	PointsPerTick       float64 `yaml:"points_per_tick"`
	PointsPerStolenFlag float64 `yaml:"points_per_stolen_flag"`
	PointsPerLostFlag   float64 `yaml:"points_per_lost_flag"`
}

type TimelineEvent struct {
	At    Duration `yaml:"at"`
	Event string   `yaml:"event"`
}

func (tl *TimelineEvent) Tick(game *AttackDefenseGame) int64 {
	return tl.At.Nanoseconds() / game.Config.TickRate.Nanoseconds()
}

func (tl *TimelineEvent) Run(ctx context.Context, game *AttackDefenseGame) error {
	return game.RunEvent(ctx, tl.Event)
}

type PageConfig struct {
	Path  string `yaml:"path"`
	Title string `yaml:"title"`
}

type Config struct {
	basePath string

	Version       int                   `yaml:"version"`
	Title         string                `yaml:"title"`
	Wait          bool                  `yaml:"wait"`
	WaitAfter     bool                  `yaml:"wait_after"`
	Vulnbox       VulnboxConfig         `yaml:"vulnbox"`
	Device        DeviceGlobalConfig    `yaml:"device"`
	ScoreBot      ScoreBotConfig        `yaml:"scorebot"`
	TickRate      Duration              `yaml:"tick_rate"`
	Duration      Duration              `yaml:"duration"`
	FlagValidTime Duration              `yaml:"flag_valid_time"`
	Scoring       ScoringConfig         `yaml:"scoring"`
	Timeline      []TimelineEvent       `yaml:"timeline"`
	Pages         map[string]PageConfig `yaml:"pages"`
}

package main

import "fmt"

const CURRENT_CONFIG_VERSION = 1

type TinyRangeConfig struct {
	Path string `yaml:"path"`
}

type FrontendConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

func (f *FrontendConfig) Url() string {
	return fmt.Sprintf("http://%s:%d", f.Address, f.Port)
}

type ServiceConfig struct {
	Port int `yaml:"port"`
}

type VulnboxConfig struct {
	Template     string                   `yaml:"template"`
	InitTemplate string                   `yaml:"init"`
	Services     map[string]ServiceConfig `yaml:"services"`
}

type EventDefinition struct {
	Command string `yaml:"command"`
}

type EventMap map[string]EventDefinition

type BotConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Template string   `yaml:"template"`
	Events   EventMap `yaml:"events"`
}

func (b *BotConfig) Start() (*TinyRangeInstance, error) {
	return nil, fmt.Errorf("BotConfig.Start not implemented")
}

type TimelineEvent struct {
	At    Duration `yaml:"at"`
	Event string   `yaml:"event"`
}

func (tl *TimelineEvent) Tick(game *AttackDefenseGame) int64 {
	return tl.At.Nanoseconds() / game.Config.TickRate.Nanoseconds()
}

func (tl *TimelineEvent) Run(game *AttackDefenseGame) error {
	return game.RunEvent(tl.Event)
}

type Config struct {
	basePath string

	Version       int             `yaml:"version"`
	TinyRange     TinyRangeConfig `yaml:"tinyrange"`
	Frontend      FrontendConfig  `yaml:"frontend"`
	Vulnbox       VulnboxConfig   `yaml:"vulnbox"`
	Bots          BotConfig       `yaml:"bots"`
	ScoreBot      ScoreBotConfig  `yaml:"scorebot"`
	TickRate      Duration        `yaml:"tick_rate"`
	Duration      Duration        `yaml:"duration"`
	FlagValidTime Duration        `yaml:"flag_valid_time"`
	Timeline      []TimelineEvent `yaml:"timeline"`
}

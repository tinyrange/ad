package main

const CURRENT_CONFIG_VERSION = 1

type ServiceConfig struct {
	Id   int    `yaml:"id"`
	Name string `yaml:"name"`
	Port int    `yaml:"port"`
}

type VulnboxConfig struct {
	Template     string          `yaml:"template"`
	InitTemplate string          `yaml:"init"`
	Services     []ServiceConfig `yaml:"services"`
	Bot          BotConfig       `yaml:"bot"`
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

func (tl *TimelineEvent) Run(game *AttackDefenseGame) error {
	return game.RunEvent(tl.Event)
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
	ScoreBot      ScoreBotConfig        `yaml:"scorebot"`
	TickRate      Duration              `yaml:"tick_rate"`
	Duration      Duration              `yaml:"duration"`
	FlagValidTime Duration              `yaml:"flag_valid_time"`
	Scoring       ScoringConfig         `yaml:"scoring"`
	Timeline      []TimelineEvent       `yaml:"timeline"`
	Pages         map[string]PageConfig `yaml:"pages"`
}

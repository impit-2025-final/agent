package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Service struct {
		URL            string `yaml:"url"`
		Token          string `yaml:"token"`
		UpdateInterval int    `yaml:"update_interval"`
	} `yaml:"service"`

	Docker struct {
		Network          string   `yaml:"network"`
		IgnoreContainers []string `yaml:"ignore_containers"`
	} `yaml:"docker"`

	Node struct {
		Name string `yaml:"name"`
	} `yaml:"node"`
}

func NewConfig() (*Config, error) {
	cfg := &Config{}

	configPath := filepath.Join("./", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if cfg.Node.Name == "" {
		cfg.Node.Name = os.Getenv("HOSTNAME")
	}

	return cfg, nil
}

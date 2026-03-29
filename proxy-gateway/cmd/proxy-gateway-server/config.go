package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"proxy-gateway/utils"
)

// Config is the top-level server configuration.
type Config struct {
	BindAddr   string `toml:"bind_addr"  yaml:"bind_addr"  json:"bind_addr"`
	Socks5Addr string `toml:"socks5_addr" yaml:"socks5_addr" json:"socks5_addr"`
	AdminAddr  string `toml:"admin_addr"  yaml:"admin_addr"  json:"admin_addr"`
	LogLevel   string `toml:"log_level"  yaml:"log_level"  json:"log_level"`

	// Auth supports a single user via sub+password, or multiple users via Users map.
	// If both are set, Users takes precedence.
	AuthSub      string            `toml:"auth_sub"      yaml:"auth_sub"      json:"auth_sub"`
	AuthPassword string            `toml:"auth_password" yaml:"auth_password" json:"auth_password"`
	Users        map[string]string `toml:"users"         yaml:"users"         json:"users"`

	ProxySets []ProxySetConfig `toml:"proxy_set" yaml:"proxy_set" json:"proxy_set"`
}

// ProxySetConfig describes one named proxy set in the config file.
type ProxySetConfig struct {
	Name       string `toml:"name"        yaml:"name"        json:"name"`
	SourceType string `toml:"source_type" yaml:"source_type" json:"source_type"`

	// Source is parsed lazily into a typed config by buildSource.
	StaticFile   *utils.StaticFileConfig   `toml:"static_file"  yaml:"static_file"  json:"static_file"`
	Bottingtools *utils.BottingtoolsConfig `toml:"bottingtools" yaml:"bottingtools" json:"bottingtools"`
	Geonode      *utils.GeonodeConfig      `toml:"geonode"      yaml:"geonode"      json:"geonode"`
}

// authUsers returns the effective user map from config.
func (c *Config) authUsers() (map[string]string, error) {
	if len(c.Users) > 0 {
		return c.Users, nil
	}
	if c.AuthSub != "" && c.AuthPassword != "" {
		return map[string]string{c.AuthSub: c.AuthPassword}, nil
	}
	return nil, fmt.Errorf("no auth configured: set users or auth_sub+auth_password")
}

// LoadConfig reads and parses a TOML, YAML, or JSON config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg := &Config{
		BindAddr: "127.0.0.1:8100",
		LogLevel: "info",
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, cfg)
	case ".json":
		err = json.Unmarshal(data, cfg)
	default:
		err = toml.Unmarshal(data, cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}

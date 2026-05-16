package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"proxy-kit/utils"
)

// Config is the top-level server configuration.
type Config struct {
	BindAddr   string `toml:"bind_addr"  yaml:"bind_addr"  json:"bind_addr"`
	Socks5Addr string `toml:"socks5_addr" yaml:"socks5_addr" json:"socks5_addr"`
	AdminAddr  string `toml:"admin_addr"  yaml:"admin_addr"  json:"admin_addr"`
	LogLevel   string `toml:"log_level"  yaml:"log_level"  json:"log_level"`

	// MITMCACert and MITMCAKey are paths to PEM-encoded CA certificate and
	// private key used for MITM TLS interception. When omitted, a new CA is
	// generated at startup.
	MITMCACert string `toml:"mitm_ca_cert" yaml:"mitm_ca_cert" json:"mitm_ca_cert"`
	MITMCAKey  string `toml:"mitm_ca_key"  yaml:"mitm_ca_key"  json:"mitm_ca_key"`

	// Scripts is the registry of named Starlark scripts. Each entry is
	// compiled at config load; references from `default_scripts` on a
	// proxy_set or from the `scripts` array in a username's JSON are looked
	// up here.
	Scripts []ScriptConfig `toml:"script" yaml:"script" json:"script"`

	ProxySets []ProxySetConfig `toml:"proxy_set" yaml:"proxy_set" json:"proxy_set"`

	// registry is built at LoadConfig from Scripts. Populated only when
	// LoadConfig succeeds.
	registry scriptMap `toml:"-" yaml:"-" json:"-"`
}

// Registry returns the script registry built from this config's `[[script]]`
// entries, or nil if the config has no scripts.
func (c *Config) Registry() ScriptRegistry {
	if c == nil || len(c.registry) == 0 {
		return nil
	}
	return c.registry
}

// ScriptConfig declares one named Starlark script. The name is referenced
// from `default_scripts` on proxy_set entries and from `scripts` arrays in
// usernames. The source is compiled once at config load; bad source fails
// the gateway at boot.
type ScriptConfig struct {
	Name   string `toml:"name"   yaml:"name"   json:"name"`
	Source string `toml:"source" yaml:"source" json:"source"`
}

// ProxySetConfig describes one named proxy set in the config file.
type ProxySetConfig struct {
	Name       string `toml:"name"     yaml:"name"     json:"name"`
	SourceType string `toml:"provider" yaml:"provider" json:"provider"`

	StaticFile   *utils.StaticFileConfig   `toml:"static_file"  yaml:"static_file"  json:"static_file"`
	Bottingtools *utils.BottingtoolsConfig `toml:"bottingtools" yaml:"bottingtools" json:"bottingtools"`
	Geonode      *utils.GeonodeConfig      `toml:"geonode"      yaml:"geonode"      json:"geonode"`
	ProxyingIO   *utils.ProxyingIOConfig   `toml:"proxyingio"   yaml:"proxyingio"   json:"proxyingio"`
	Webshare     *utils.WebshareConfig     `toml:"webshare"     yaml:"webshare"     json:"webshare"`

	// DefaultScripts is the ordered chain of named scripts to apply when
	// the per-request username doesn't carry its own `scripts` array. Names
	// must resolve to entries in the top-level [[script]] table.
	DefaultScripts []string `toml:"default_scripts" yaml:"default_scripts" json:"default_scripts"`

	// resolvedDefaults holds the pre-resolved chain. Populated by LoadConfig.
	resolvedDefaults []*Script `toml:"-" yaml:"-" json:"-"`
}

// ResolvedDefaults returns the per-set default chain, already resolved from
// the script registry. Empty when no defaults are configured.
func (p *ProxySetConfig) ResolvedDefaults() []*Script {
	if p == nil {
		return nil
	}
	return p.resolvedDefaults
}

// LoadConfig reads and parses a TOML, YAML, or JSON config file. It compiles
// every named script and resolves each proxy_set's `default_scripts` list,
// failing the boot on bad source or unknown references.
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

	// Compile every named script. Duplicates are rejected.
	cfg.registry = scriptMap{}
	for i := range cfg.Scripts {
		sc := &cfg.Scripts[i]
		if sc.Name == "" {
			return nil, fmt.Errorf("[[script]] entry %d: name must not be empty", i)
		}
		if _, dup := cfg.registry[sc.Name]; dup {
			return nil, fmt.Errorf("[[script]] duplicate name %q", sc.Name)
		}
		compiled, cerr := Compile("config:"+sc.Name, sc.Source)
		if cerr != nil {
			return nil, fmt.Errorf("[[script]] %q: %w", sc.Name, cerr)
		}
		cfg.registry[sc.Name] = compiled
	}

	// Resolve each proxy_set's default_scripts list against the registry.
	for i := range cfg.ProxySets {
		ps := &cfg.ProxySets[i]
		if len(ps.DefaultScripts) == 0 {
			continue
		}
		ps.resolvedDefaults = make([]*Script, 0, len(ps.DefaultScripts))
		for j, name := range ps.DefaultScripts {
			s, ok := cfg.registry[name]
			if !ok {
				return nil, fmt.Errorf("proxy_set %q default_scripts[%d]: unknown script %q", ps.Name, j, name)
			}
			ps.resolvedDefaults = append(ps.resolvedDefaults, s)
		}
	}

	return cfg, nil
}

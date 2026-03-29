package utils

import (
	"context"
	"fmt"
	"os"
	"strings"

	"proxy-gateway/core"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// BottingtoolsConfig is the configuration for the bottingtools proxy source.
type BottingtoolsConfig struct {
	Username    string                    `toml:"username"     yaml:"username"     json:"username"`
	PasswordEnv string                    `toml:"password_env" yaml:"password_env" json:"password_env"`
	Host        string                    `toml:"host"         yaml:"host"         json:"host"`
	Product     BottingtoolsProductConfig `toml:"product"      yaml:"product"      json:"product"`
}

// BottingtoolsProductConfig holds the product type and its specific parameters.
type BottingtoolsProductConfig struct {
	Type        string                         `toml:"type" yaml:"type" json:"type"`
	Residential *BottingtoolsResidentialConfig `toml:"-"    yaml:"-"    json:"-"`
	ISP         *BottingtoolsISPConfig         `toml:"-"    yaml:"-"    json:"-"`
	Datacenter  *BottingtoolsDatacenterConfig  `toml:"-"    yaml:"-"    json:"-"`
}

// BottingtoolsResidentialConfig holds residential-specific parameters.
type BottingtoolsResidentialConfig struct {
	Quality   BottingtoolsResidentialQuality `toml:"quality"   yaml:"quality"   json:"quality"`
	Countries []Country                      `toml:"countries" yaml:"countries" json:"countries"`
	City      string                         `toml:"city"      yaml:"city"      json:"city"`
}

// Validate checks residential config constraints.
func (r *BottingtoolsResidentialConfig) Validate() error {
	if r.City != "" && len(r.Countries) != 1 {
		return fmt.Errorf("residential `city` requires exactly one country, but %d are configured", len(r.Countries))
	}
	return nil
}

// BottingtoolsISPConfig holds ISP-specific parameters.
type BottingtoolsISPConfig struct {
	Countries []Country `toml:"countries" yaml:"countries" json:"countries"`
}

// BottingtoolsDatacenterConfig holds datacenter-specific parameters.
type BottingtoolsDatacenterConfig struct {
	Countries []Country `toml:"countries" yaml:"countries" json:"countries"`
}

// BottingtoolsResidentialQuality is the residential proxy quality tier.
type BottingtoolsResidentialQuality string

const (
	BottingtoolsResidentialQualityLow  BottingtoolsResidentialQuality = "low"
	BottingtoolsResidentialQualityHigh BottingtoolsResidentialQuality = "high"
)

// AsTypeStr returns the string used in the upstream username.
func (q BottingtoolsResidentialQuality) AsTypeStr() string {
	if q == BottingtoolsResidentialQualityLow {
		return "low"
	}
	return "high"
}

// BottingtoolsRawProductConfig is used for unmarshaling before dispatching to the typed config.
type BottingtoolsRawProductConfig struct {
	Type      string    `toml:"type"      yaml:"type"      json:"type"`
	Quality   string    `toml:"quality"   yaml:"quality"   json:"quality"`
	Countries []Country `toml:"countries" yaml:"countries" json:"countries"`
	City      string    `toml:"city"      yaml:"city"      json:"city"`
	SessTime  int       `toml:"sess_time" yaml:"sess_time" json:"sess_time"`
}

// ParseBottingtoolsProductConfig converts a raw product table into a typed config.
func ParseBottingtoolsProductConfig(raw BottingtoolsRawProductConfig) (BottingtoolsProductConfig, error) {
	switch raw.Type {
	case "residential":
		quality := BottingtoolsResidentialQualityHigh
		if raw.Quality == "low" {
			quality = BottingtoolsResidentialQualityLow
		}
		cfg := &BottingtoolsResidentialConfig{
			Quality:   quality,
			Countries: raw.Countries,
			City:      raw.City,
		}
		if err := cfg.Validate(); err != nil {
			return BottingtoolsProductConfig{}, err
		}
		return BottingtoolsProductConfig{Type: "residential", Residential: cfg}, nil
	case "isp":
		return BottingtoolsProductConfig{Type: "isp", ISP: &BottingtoolsISPConfig{Countries: raw.Countries}}, nil
	case "datacenter":
		return BottingtoolsProductConfig{Type: "datacenter", Datacenter: &BottingtoolsDatacenterConfig{Countries: raw.Countries}}, nil
	default:
		return BottingtoolsProductConfig{}, fmt.Errorf("unknown bottingtools product type %q (expected: residential, isp, datacenter)", raw.Type)
	}
}

// ---------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------

// BottingtoolsSource is a proxy source backed by the bottingtools API.
type BottingtoolsSource struct {
	accountUser string
	password    string
	host        string
	product     BottingtoolsProductConfig
}

// NewBottingtoolsSource creates a BottingtoolsSource from config.
func NewBottingtoolsSource(cfg *BottingtoolsConfig) (*BottingtoolsSource, error) {
	password := os.Getenv(cfg.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("environment variable %q not set or empty", cfg.PasswordEnv)
	}
	return &BottingtoolsSource{
		accountUser: cfg.Username,
		password:    password,
		host:        cfg.Host,
		product:     cfg.Product,
	}, nil
}

// Resolve implements core.Handler.
func (s *BottingtoolsSource) Resolve(ctx context.Context, _ *core.Request) (*core.Result, error) {
	username := btBuildUsername(s.accountUser, s.product, GetMeta(ctx))
	return core.Resolved(&core.Proxy{
		Host:     s.host,
		Port:     1337,
		Username: username,
		Password: s.password,
	}), nil
}

// Describe returns a human-readable description.
func (s *BottingtoolsSource) Describe() string {
	var product string
	switch s.product.Type {
	case "residential":
		product = fmt.Sprintf("residential(%s)", s.product.Residential.Quality.AsTypeStr())
	case "isp":
		product = "isp"
	case "datacenter":
		product = "datacenter"
	}
	return fmt.Sprintf("bottingtools %s %s@%s", product, s.accountUser, s.host)
}

// ---------------------------------------------------------------------------
// Username building
// ---------------------------------------------------------------------------

func btBuildUsername(accountUser string, product BottingtoolsProductConfig, meta Meta) string {
	switch product.Type {
	case "residential":
		return btBuildResidential(accountUser, product.Residential, meta)
	case "isp":
		return btBuildISP(accountUser, product.ISP, meta)
	case "datacenter":
		return btBuildDatacenter(accountUser, product.Datacenter)
	default:
		return accountUser
	}
}

func btBuildResidential(accountUser string, cfg *BottingtoolsResidentialConfig, meta Meta) string {
	parts := []string{fmt.Sprintf("%s_pool-custom_type-%s", accountUser, cfg.Quality.AsTypeStr())}
	if country := btPickCountry(cfg.Countries); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", strings.ToUpper(country.AsParamStr())))
	}
	if cfg.City != "" {
		parts = append(parts, fmt.Sprintf("city-%s", cfg.City))
	}
	parts = append(parts, fmt.Sprintf("session-%s", btRandomSessionID()))
	if v := btSesstimeStr(meta); v != "" {
		parts = append(parts, fmt.Sprintf("sesstime-%s", v))
	}
	if meta.GetString("fastmode") == "true" {
		parts = append(parts, "fastmode-true")
	}
	return strings.Join(parts, "_")
}

func btBuildISP(accountUser string, cfg *BottingtoolsISPConfig, meta Meta) string {
	parts := []string{fmt.Sprintf("%s_pool-isp", accountUser)}
	if country := btPickCountry(cfg.Countries); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", country.AsParamStr()))
	}
	parts = append(parts, fmt.Sprintf("session-%s", btRandomSessionID()))
	if v := btSesstimeStr(meta); v != "" {
		parts = append(parts, fmt.Sprintf("sesstime-%s", v))
	}
	return strings.Join(parts, "_")
}

func btBuildDatacenter(accountUser string, cfg *BottingtoolsDatacenterConfig) string {
	parts := []string{fmt.Sprintf("%s_pool-dc", accountUser)}
	if country := btPickCountry(cfg.Countries); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", country.AsParamStr()))
	}
	return strings.Join(parts, "_")
}

// BottingtoolsRotateSessionID replaces the session ID in a bottingtools username.
func BottingtoolsRotateSessionID(username string) string {
	newID := btRandomSessionID()
	parts := strings.Split(username, "_")
	replaced := false
	for i, part := range parts {
		if !replaced && strings.HasPrefix(part, "session-") {
			parts[i] = "session-" + newID
			replaced = true
		}
	}
	return strings.Join(parts, "_")
}

func btPickCountry(countries []Country) Country {
	if len(countries) == 0 {
		return ""
	}
	return countries[int(CheapRandom())%len(countries)]
}

func btSesstimeStr(meta Meta) string {
	v := meta["sesstime"]
	if v == nil {
		return ""
	}
	switch vv := v.(type) {
	case string:
		return vv
	case float64:
		return fmt.Sprintf("%g", vv)
	default:
		return fmt.Sprintf("%v", vv)
	}
}

func btRandomSessionID() string {
	a := CheapRandom()
	b := CheapRandom()
	return fmt.Sprintf("%016x", a^(b<<32))
}

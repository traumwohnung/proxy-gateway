package bottingtools

import (
	"fmt"

	"proxy-gateway/utils"
)

// Config is the configuration for the bottingtools proxy source.
type Config struct {
	Username    string        `toml:"username"     yaml:"username"     json:"username"`
	PasswordEnv string        `toml:"password_env" yaml:"password_env" json:"password_env"`
	Host        string        `toml:"host"         yaml:"host"         json:"host"`
	Product     ProductConfig `toml:"product"      yaml:"product"      json:"product"`
}

// ProductConfig holds the product type and its specific parameters.
type ProductConfig struct {
	Type        string             `toml:"type" yaml:"type" json:"type"`
	Residential *ResidentialConfig `toml:"-"    yaml:"-"    json:"-"`
	ISP         *ISPConfig         `toml:"-"    yaml:"-"    json:"-"`
	Datacenter  *DatacenterConfig  `toml:"-"    yaml:"-"    json:"-"`
}

// ResidentialConfig holds residential-specific parameters.
type ResidentialConfig struct {
	Quality   ResidentialQuality `toml:"quality"   yaml:"quality"   json:"quality"`
	Countries []utils.Country    `toml:"countries" yaml:"countries" json:"countries"`
	City      string             `toml:"city"      yaml:"city"      json:"city"`
}

// Validate checks residential config constraints.
func (r *ResidentialConfig) Validate() error {
	if r.City != "" && len(r.Countries) != 1 {
		return fmt.Errorf("residential `city` requires exactly one country, but %d are configured", len(r.Countries))
	}
	return nil
}

// ISPConfig holds ISP-specific parameters.
type ISPConfig struct {
	Countries []utils.Country `toml:"countries" yaml:"countries" json:"countries"`
}

// DatacenterConfig holds datacenter-specific parameters.
type DatacenterConfig struct {
	Countries []utils.Country `toml:"countries" yaml:"countries" json:"countries"`
}

// ResidentialQuality is the residential proxy quality tier.
type ResidentialQuality string

const (
	ResidentialQualityLow  ResidentialQuality = "low"
	ResidentialQualityHigh ResidentialQuality = "high"
)

// AsTypeStr returns the string used in the upstream username.
func (q ResidentialQuality) AsTypeStr() string {
	if q == ResidentialQualityLow {
		return "low"
	}
	return "high"
}

// RawProductConfig is used for unmarshaling before dispatching to the typed config.
type RawProductConfig struct {
	Type      string          `toml:"type"      yaml:"type"      json:"type"`
	Quality   string          `toml:"quality"   yaml:"quality"   json:"quality"`
	Countries []utils.Country `toml:"countries" yaml:"countries" json:"countries"`
	City      string          `toml:"city"      yaml:"city"      json:"city"`
	SessTime  int             `toml:"sess_time" yaml:"sess_time" json:"sess_time"`
}

// ParseProductConfig converts a raw product table into a typed ProductConfig.
func ParseProductConfig(raw RawProductConfig) (ProductConfig, error) {
	switch raw.Type {
	case "residential":
		quality := ResidentialQualityHigh
		if raw.Quality == "low" {
			quality = ResidentialQualityLow
		}
		cfg := &ResidentialConfig{
			Quality:   quality,
			Countries: raw.Countries,
			City:      raw.City,
		}
		if err := cfg.Validate(); err != nil {
			return ProductConfig{}, err
		}
		return ProductConfig{Type: "residential", Residential: cfg}, nil
	case "isp":
		return ProductConfig{Type: "isp", ISP: &ISPConfig{Countries: raw.Countries}}, nil
	case "datacenter":
		return ProductConfig{Type: "datacenter", Datacenter: &DatacenterConfig{Countries: raw.Countries}}, nil
	default:
		return ProductConfig{}, fmt.Errorf("unknown bottingtools product type %q (expected: residential, isp, datacenter)", raw.Type)
	}
}

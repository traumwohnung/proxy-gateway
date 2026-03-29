package main

import (
	"fmt"

	"proxy-gateway/core"
	"proxy-gateway/utils"
)

// buildSource constructs a proxy source Handler from a ProxySetConfig.
// Source configs are unmarshaled directly via TOML/YAML typed structs —
// no JSON double-pass, no normalizeMap.
func buildSource(raw *ProxySetConfig, configDir string) (core.Handler, error) {
	switch raw.SourceType {
	case "static_file":
		if raw.StaticFile == nil {
			return nil, fmt.Errorf("static_file source requires a [static_file] section")
		}
		cfg := raw.StaticFile
		if cfg.Format == "" {
			cfg.Format = utils.DefaultProxyFormat
		}
		return utils.NewStaticFileSource(cfg, configDir)

	case "bottingtools":
		if raw.Bottingtools == nil {
			return nil, fmt.Errorf("bottingtools source requires a [bottingtools] section")
		}
		return utils.NewBottingtoolsSource(raw.Bottingtools)

	case "geonode":
		if raw.Geonode == nil {
			return nil, fmt.Errorf("geonode source requires a [geonode] section")
		}
		cfg := raw.Geonode
		if cfg.Protocol == "" {
			cfg.Protocol = utils.GeonodeProtocolHTTP
		}
		if cfg.Session.Type == "" {
			cfg.Session.Type = utils.GeonodeSessionRotating
		}
		return utils.NewGeonodeSource(cfg)

	default:
		return nil, fmt.Errorf("unknown source type %q (supported: static_file, bottingtools, geonode)", raw.SourceType)
	}
}

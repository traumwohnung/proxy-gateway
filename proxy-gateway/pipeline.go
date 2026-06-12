package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	proxykit "proxy-kit"
	"proxy-kit/utils"
)

// Server holds the assembled pipeline and all introspection handles.
type Server struct {
	Pipeline proxykit.Handler
	Sessions *utils.SessionManager
	Usage    *UsageTracker
}

// BuildServer assembles the full handler pipeline from config.
func BuildServer(cfg *Config, configDir string, proxyPassword string, tracker *UsageTracker) (*Server, error) {
	router, err := buildProxysetRouter(cfg, configDir)
	if err != nil {
		return nil, err
	}

	var listener utils.EpochListener
	if tracker != nil {
		// nil-safe: returns nil when tracker.client is nil (analytics disabled).
		if l := newAnalyticsEpochListener(tracker.client); l != nil {
			listener = l
		}
	}
	sessions := utils.NewSessionManagerWithListener(router, listener)
	inner := trackUsage(tracker, sessions, sessions)

	ca, err := loadOrGenerateCA(cfg, configDir)
	if err != nil {
		return nil, err
	}

	conditionalMITM := utils.ConditionalMITM(ca, getHTTPCloakSpec, inner)
	allowlist := NewDestinationAllowlist(cfg.DestinationAllowlist)
	if allowlist == nil {
		slog.Warn("destination allowlist is empty — gateway will proxy to ANY destination (set destination_allowlist)")
	}
	guarded := AllowDestinations(allowlist, ParseJSONCreds(cfg.Registry(), conditionalMITM))
	pipeline := PasswordAuth(proxyPassword, guarded)

	return &Server{
		Pipeline: pipeline,
		Sessions: sessions,
		Usage:    tracker,
	}, nil
}

// buildProxysetRouter creates a Handler that dispatches to the correct proxy
// source based on the set name in context.
func buildProxysetRouter(cfg *Config, configDir string) (proxykit.Handler, error) {
	sources := make(map[string]proxykit.Handler, len(cfg.ProxySets))
	for _, raw := range cfg.ProxySets {
		var src proxykit.Handler
		var err error

		switch raw.SourceType {
		case "static_file":
			if raw.StaticFile == nil {
				return nil, fmt.Errorf("proxy set %q: static_file source requires a [static_file] section", raw.Name)
			}
			c := raw.StaticFile
			if c.Format == "" {
				c.Format = utils.DefaultProxyFormat
			}
			src, err = utils.NewStaticFileSource(c, configDir)

		case "bottingtools":
			if raw.Bottingtools == nil {
				return nil, fmt.Errorf("proxy set %q: bottingtools source requires a [bottingtools] section", raw.Name)
			}
			src, err = utils.NewBottingtoolsSource(raw.Bottingtools)

		case "geonode":
			if raw.Geonode == nil {
				return nil, fmt.Errorf("proxy set %q: geonode source requires a [geonode] section", raw.Name)
			}
			c := raw.Geonode
			if c.Protocol == "" {
				c.Protocol = utils.GeonodeProtocolHTTP
			}
			if c.Session.Type == "" {
				c.Session.Type = utils.GeonodeSessionRotating
			}
			src, err = utils.NewGeonodeSource(c)

		case "proxyingio":
			if raw.ProxyingIO == nil {
				return nil, fmt.Errorf("proxy set %q: proxyingio source requires a [proxyingio] section", raw.Name)
			}
			src, err = utils.NewProxyingIOSource(raw.ProxyingIO)

		case "webshare":
			if raw.Webshare == nil {
				return nil, fmt.Errorf("proxy set %q: webshare source requires a [webshare] section", raw.Name)
			}
			src, err = utils.NewWebshareSource(raw.Webshare)

		case "none":
			src = utils.NewNoneSource()

		default:
			return nil, fmt.Errorf("proxy set %q: unknown source type %q (supported: static_file, bottingtools, geonode, proxyingio, webshare, none)", raw.Name, raw.SourceType)
		}

		if err != nil {
			return nil, fmt.Errorf("proxy set %q: %w", raw.Name, err)
		}
		// Tag the source with its provider type so emission downstream knows
		// which upstream produced this binding. Captured by value so each set
		// gets its own closure.
		provider := raw.SourceType
		baseSrc := src
		sources[raw.Name] = proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
			ctx = utils.WithProviderName(ctx, provider)
			result, err := baseSrc.Resolve(ctx, req)
			if err != nil || result == nil {
				return result, err
			}
			// Install a response hook only when the username's
			// `mitm.scripts` array contributed at least one script.
			chain := getScripts(ctx)
			if len(chain) > 0 {
				prev := result.ResponseHook
				hookCtx := ctx
				result.ResponseHook = func(resp *http.Response) *http.Response {
					if prev != nil {
						resp = prev(resp)
					}
					return ApplyResponseBailing(hookCtx, chain, resp, 0, 0)
				}
			}
			return result, nil
		})
	}

	return proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		set := getSet(ctx)
		h, ok := sources[set]
		if !ok {
			return nil, fmt.Errorf("unknown proxy set %q", set)
		}
		return h.Resolve(ctx, req)
	}), nil
}

// epochLookup is the minimum SessionManager surface trackUsage needs to
// snapshot the active epoch onto each connection. Decoupled so tests can
// inject a fake.
type epochLookup interface {
	GetSession(topLevelSeed uint64) *utils.SessionInfo
}

// trackUsage wraps next and chains a usageConnTracker onto every Result so
// that byte totals are recorded when each connection closes. epochSrc is
// queried after next.Resolve to snapshot the current epoch for the session;
// pass nil to disable epoch lookup (epoch=0 on every event).
// If tracker is nil the middleware is a no-op passthrough.
func trackUsage(tracker *UsageTracker, epochSrc epochLookup, next proxykit.Handler) proxykit.Handler {
	if tracker == nil {
		return next
	}
	return proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		result, err := next.Resolve(ctx, req)
		if err != nil || result == nil {
			return result, err
		}
		upstreamIP := ""
		if result.Proxy != nil {
			upstreamIP = result.Proxy.Host
		}
		var epoch int32
		if epochSrc != nil {
			if info := epochSrc.GetSession(utils.GetTopLevelSeed(ctx)); info != nil {
				epoch = info.Epoch
			}
		}
		ct := &usageConnTracker{
			tracker: tracker,
			rec: connRecord{
				connectionID:  newConnectionID(),
				proxyset:      getSet(ctx),
				provider:      utils.GetProviderName(ctx),
				sessionParams: utils.GetSessionParamsJSON(ctx),
				sessionMeta:   getSessionMetaJSON(ctx),
				minutes:       getMinutes(ctx),
				epoch:         epoch,
				upstreamIP:    upstreamIP,
				startedAt:     time.Now().UTC(),
			},
		}
		result.ConnTracker = proxykit.ChainTrackers(result.ConnTracker, ct)
		return result, nil
	})
}

// loadOrGenerateCA loads a MITM CA from config paths, or generates a new one.
func loadOrGenerateCA(cfg *Config, configDir string) (tls.Certificate, error) {
	if cfg.MITMCACert != "" && cfg.MITMCAKey != "" {
		certPath := cfg.MITMCACert
		keyPath := cfg.MITMCAKey
		if !filepath.IsAbs(certPath) {
			certPath = filepath.Join(configDir, certPath)
		}
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(configDir, keyPath)
		}
		ca, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("loading MITM CA from %s / %s: %w", certPath, keyPath, err)
		}
		slog.Info("MITM CA loaded from file", "cert", certPath, "key", keyPath)
		return ca, nil
	}

	ca, err := proxykit.NewCA()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating MITM CA: %w", err)
	}
	slog.Info("MITM CA generated (no mitm_ca_cert/mitm_ca_key in config)")
	return ca, nil
}

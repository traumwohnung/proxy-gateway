package session

import (
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

const SessionStateVersion = 5

// SessionState represents the complete saveable session state
type SessionState struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Full session configuration - saves everything
	Config *protocol.SessionConfig `json:"config"`

	// Session data - v5 format: cookies keyed by domain
	// Key is the domain (e.g., ".example.com" for domain cookies, "example.com" for host-only)
	Cookies map[string][]CookieState `json:"cookies"`

	// TLS Sessions keyed by origin "protocol:host:port"
	// e.g., "h2:example.com:443", "h3:api.example.com:443"
	TLSSessions map[string]transport.TLSSessionState `json:"tls_sessions"`

	// ECHConfigs stores ECH configurations per domain (base64 encoded)
	// This is essential for session resumption - the same ECH config must be used
	// when resuming as was used when creating the session ticket
	ECHConfigs map[string]string `json:"ech_configs,omitempty"`
}

// SessionStateV4 represents the v4 format for migration
type SessionStateV4 struct {
	Version     int                                  `json:"version"`
	CreatedAt   time.Time                            `json:"created_at"`
	UpdatedAt   time.Time                            `json:"updated_at"`
	Config      *protocol.SessionConfig              `json:"config"`
	Cookies     []CookieState                        `json:"cookies"` // v4: flat list
	TLSSessions map[string]transport.TLSSessionState `json:"tls_sessions"`
	ECHConfigs  map[string]string                    `json:"ech_configs,omitempty"`
}

// CookieState represents a serializable cookie with full metadata
type CookieState struct {
	Name      string     `json:"name"`
	Value     string     `json:"value"`
	Domain    string     `json:"domain,omitempty"`
	Path      string     `json:"path,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
	MaxAge    int        `json:"max_age,omitempty"`
	Secure    bool       `json:"secure,omitempty"`
	HttpOnly  bool       `json:"http_only,omitempty"`
	SameSite  string     `json:"same_site,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"` // v5: for sorting
}

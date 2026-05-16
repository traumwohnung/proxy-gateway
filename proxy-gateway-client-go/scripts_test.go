package proxygatewayclient_test

import (
	"encoding/json"
	"strings"
	"testing"

	proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"
)

func TestScriptEntry_Marshal_Ref(t *testing.T) {
	e := proxygatewayclient.ScriptRef("antibot")
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"kind":"ref","name":"antibot"}` {
		t.Fatalf("got %q", b)
	}
}

func TestScriptEntry_Marshal_Source(t *testing.T) {
	e := proxygatewayclient.ScriptSource("def response_bailing(r): return None")
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"source":"def response_bailing(r):`) {
		t.Fatalf("got %q", b)
	}
}

func TestScriptEntry_Marshal_BothFieldsErrors(t *testing.T) {
	e := proxygatewayclient.ScriptEntry{Kind: proxygatewayclient.ScriptEntryKindRef, Name: "a", Source: "b"}
	if _, err := json.Marshal(e); err == nil {
		t.Fatal("want error when both fields set")
	}
}

func TestScriptEntry_Marshal_NeitherFieldErrors(t *testing.T) {
	if _, err := json.Marshal(proxygatewayclient.ScriptEntry{}); err == nil {
		t.Fatal("want error when neither field set")
	}
}

func TestScriptEntry_Unmarshal_BareString(t *testing.T) {
	var e proxygatewayclient.ScriptEntry
	if err := json.Unmarshal([]byte(`"antibot"`), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Name != "antibot" {
		t.Fatalf("Ref=%q", e.Name)
	}
	if e.Source != "" {
		t.Fatalf("Source should be empty, got %q", e.Source)
	}
}

func TestScriptEntry_Unmarshal_RefObject(t *testing.T) {
	var e proxygatewayclient.ScriptEntry
	if err := json.Unmarshal([]byte(`{"kind":"ref","name":"antibot"}`), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Name != "antibot" || e.Source != "" {
		t.Fatalf("Ref=%q Source=%q", e.Name, e.Source)
	}
}

func TestScriptEntry_Unmarshal_SourceObject(t *testing.T) {
	var e proxygatewayclient.ScriptEntry
	if err := json.Unmarshal([]byte(`{"kind":"source","source":"def response_bailing(r): pass"}`), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Source == "" || e.Name != "" {
		t.Fatalf("Ref=%q Source=%q", e.Name, e.Source)
	}
}

func TestScriptEntry_Unmarshal_KindRefIgnoresExtraSource(t *testing.T) {
	// kind=ref with an extra source field: the source is ignored because
	// the kind discriminator is authoritative.
	var e proxygatewayclient.ScriptEntry
	if err := json.Unmarshal([]byte(`{"kind":"ref","name":"a","source":"ignored"}`), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Name != "a" || e.Source != "" {
		t.Fatalf("Name=%q Source=%q", e.Name, e.Source)
	}
}

func TestScriptEntry_Unmarshal_MissingKindErrors(t *testing.T) {
	var e proxygatewayclient.ScriptEntry
	err := json.Unmarshal([]byte(`{}`), &e)
	if err == nil || !strings.Contains(err.Error(), "missing 'kind'") {
		t.Fatalf("want missing-kind error, got %v", err)
	}
}

func TestScriptEntry_Unmarshal_UnknownKindErrors(t *testing.T) {
	var e proxygatewayclient.ScriptEntry
	err := json.Unmarshal([]byte(`{"kind":"nonsense"}`), &e)
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("want unknown-kind error, got %v", err)
	}
}

// ── ProxyConfiguration.Scripts / ScriptRef / ScriptSource / ClearScripts ──

func TestProxyConfiguration_ScriptsAppend(t *testing.T) {
	c := proxygatewayclient.NewProxyConfiguration("set").
		ScriptRef("antibot").
		ScriptSource(`def response_bailing(r): return None`).
		Scripts(proxygatewayclient.ScriptRef("late"))
	u, err := c.BuildUsername()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	parsed, err := proxygatewayclient.ParseUsername(u)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Scripts) != 3 {
		t.Fatalf("want 3 scripts, got %d", len(parsed.Scripts))
	}
	if parsed.Scripts[0].Name != "antibot" {
		t.Fatalf("Scripts[0].Name=%q", parsed.Scripts[0].Name)
	}
	if parsed.Scripts[1].Source == "" {
		t.Fatalf("Scripts[1].Source empty")
	}
	if parsed.Scripts[2].Name != "late" {
		t.Fatalf("Scripts[2].Name=%q", parsed.Scripts[2].Name)
	}
}

func TestProxyConfiguration_CloneCopiesScripts(t *testing.T) {
	base := proxygatewayclient.NewProxyConfiguration("set").ScriptRef("antibot")
	cp := base.Clone().ScriptRef("extra")
	if len(base.Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Clone().Scripts(proxygatewayclient.ScriptRef("x")).MustBuildUsername()) == 0 {
		t.Fatal("clone chain build returned empty")
	}
	// Confirm base wasn't mutated: still only 1 script
	bu, _ := base.BuildUsername()
	bp, _ := proxygatewayclient.ParseUsername(bu)
	if len(bp.Scripts) != 1 {
		t.Fatalf("base scripts mutated: %d", len(bp.Scripts))
	}
	// And the clone has 2
	cu, _ := cp.BuildUsername()
	cpp, _ := proxygatewayclient.ParseUsername(cu)
	if len(cpp.Scripts) != 2 {
		t.Fatalf("clone scripts=%d, want 2", len(cpp.Scripts))
	}
}

func TestProxyConfiguration_ClearScripts(t *testing.T) {
	c := proxygatewayclient.NewProxyConfiguration("set").
		ScriptRef("antibot").
		ScriptRef("more").
		ClearScripts()
	u, _ := c.BuildUsername()
	p, _ := proxygatewayclient.ParseUsername(u)
	if len(p.Scripts) != 0 {
		t.Fatalf("want 0 scripts after Clear, got %d", len(p.Scripts))
	}
}

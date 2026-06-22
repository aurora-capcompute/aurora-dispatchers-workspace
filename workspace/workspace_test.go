package workspace

import (
	"aurora-dispatchers/builtin"
	"aurora-dispatchers/registry"
	"capcompute/dispatcher"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newHandler(t *testing.T, name string, extra string) *Handler {
	t.Helper()
	root := t.TempDir()
	raw := json.RawMessage(`{"root":` + quote(root) + `,"allow_write":true,"allow_delete":true` + extra + `}`)
	normalized, err := (Registration{}).Normalize(name, raw)
	if err != nil {
		t.Fatal(err)
	}
	var settings Settings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		t.Fatal(err)
	}
	return &Handler{name: name, settings: settings}
}

func TestWriteReadAndHashConflict(t *testing.T) {
	h := newHandler(t, Write, "")
	out, err := h.DispatchCall(context.Background(), dispatcher.Call{
		Name: Write, Args: json.RawMessage(`{"path":"a.txt","content":"hello"}`),
	})
	if err != nil || out.Kind() != dispatcher.OutcomeResult {
		t.Fatalf("write = %v, %v", out.Kind(), err)
	}
	var written map[string]any
	_ = json.Unmarshal(out.Result(), &written)
	hash := written["hash"].(string)

	h.name = Read
	out, _ = h.DispatchCall(context.Background(), dispatcher.Call{Name: Read, Args: json.RawMessage(`{"path":"a.txt"}`)})
	if out.Kind() != dispatcher.OutcomeResult {
		t.Fatalf("read = %v: %s", out.Kind(), out.Message())
	}

	h.name = Write
	out, _ = h.DispatchCall(context.Background(), dispatcher.Call{
		Name: Write, Args: json.RawMessage(`{"path":"a.txt","content":"changed","expected_hash":"bad"}`),
	})
	if out.Kind() != dispatcher.OutcomeFailed {
		t.Fatalf("expected conflict, got %v (initial hash %s)", out.Kind(), hash)
	}
}

func TestTraversalAndSymlinkEscapeRejected(t *testing.T) {
	h := newHandler(t, Read, "")
	for _, args := range []string{`{"path":"../secret"}`, `{"path":"/etc/passwd"}`} {
		out, _ := h.DispatchCall(context.Background(), dispatcher.Call{Name: Read, Args: json.RawMessage(args)})
		if out.Kind() != dispatcher.OutcomeFailed {
			t.Fatalf("%s was not rejected", args)
		}
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(h.settings.Root, "link")); err != nil {
		t.Fatal(err)
	}
	out, _ := h.DispatchCall(context.Background(), dispatcher.Call{Name: Read, Args: json.RawMessage(`{"path":"link/file"}`)})
	if out.Kind() != dispatcher.OutcomeFailed {
		t.Fatal("symlink escape was not rejected")
	}
}

func TestRegistrationConfiguresCapability(t *testing.T) {
	root := t.TempDir()
	var config builtin.Config
	err := (Registration{}).Configure(context.Background(), Read, json.RawMessage(`{"root":`+quote(root)+`}`), registry.Services{}, &config)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Handlers) != 1 || len(config.Capabilities) != 1 || !json.Valid(config.Capabilities[0].InputSchema) {
		t.Fatalf("bad config: %#v", config)
	}
}

func TestSubsetRejectsWidenedWrites(t *testing.T) {
	root := t.TempDir()
	parent, _ := (Registration{}).Normalize(Read, json.RawMessage(`{"root":`+quote(root)+`}`))
	child, _ := (Registration{}).Normalize(Write, json.RawMessage(`{"root":`+quote(root)+`,"allow_write":true}`))
	if err := (Registration{}).IsSubset(Write, parent, child); err == nil {
		t.Fatal("expected widened write permission to fail")
	}
}

func quote(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

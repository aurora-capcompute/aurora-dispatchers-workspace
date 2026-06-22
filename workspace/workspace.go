package workspace

import (
	"aurora-dispatchers/builtin"
	"aurora-dispatchers/registry"
	"aurora-dispatchers/resolution"
	"bytes"
	"capcompute/dispatcher"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const (
	List   = "workspace.list"
	Stat   = "workspace.stat"
	Read   = "workspace.read"
	Search = "workspace.search"
	Write  = "workspace.write"
	Patch  = "workspace.patch"
	Mkdir  = "workspace.mkdir"
	Move   = "workspace.move"
	Delete = "workspace.delete"
)

var capabilityNames = []string{List, Stat, Read, Search, Write, Patch, Mkdir, Move, Delete}

type Settings struct {
	Root             string   `json:"root"`
	ReadAllow        []string `json:"read_allow,omitempty"`
	WriteAllow       []string `json:"write_allow,omitempty"`
	Exclude          []string `json:"exclude,omitempty"`
	MaxReadBytes     int64    `json:"max_read_bytes,omitempty"`
	MaxWriteBytes    int64    `json:"max_write_bytes,omitempty"`
	MaxSearchResults int      `json:"max_search_results,omitempty"`
	MaxFilesPerCall  int      `json:"max_files_per_call,omitempty"`
	AllowWrite       bool     `json:"allow_write,omitempty"`
	AllowDelete      bool     `json:"allow_delete,omitempty"`
	RequireApproval  bool     `json:"require_approval,omitempty"`
	FollowSymlinks   bool     `json:"follow_symlinks,omitempty"`
}

type Registration struct{}

func (Registration) Matches(name string) bool { return slices.Contains(capabilityNames, name) }

func (Registration) Normalize(name string, raw json.RawMessage) (json.RawMessage, error) {
	if !slices.Contains(capabilityNames, name) {
		return nil, fmt.Errorf("unsupported workspace capability %q", name)
	}
	settings := Settings{
		ReadAllow:        []string{"**"},
		WriteAllow:       []string{"**"},
		Exclude:          []string{".git/**"},
		MaxReadBytes:     2 << 20,
		MaxWriteBytes:    2 << 20,
		MaxSearchResults: 200,
		MaxFilesPerCall:  100,
	}
	if err := decodeStrict(raw, &settings); err != nil {
		return nil, err
	}
	root, err := canonicalRoot(settings.Root)
	if err != nil {
		return nil, err
	}
	settings.Root = root
	settings.ReadAllow, err = normalizeGlobs(settings.ReadAllow)
	if err != nil {
		return nil, fmt.Errorf("read_allow: %w", err)
	}
	settings.WriteAllow, err = normalizeGlobs(settings.WriteAllow)
	if err != nil {
		return nil, fmt.Errorf("write_allow: %w", err)
	}
	settings.Exclude, err = normalizeGlobs(settings.Exclude)
	if err != nil {
		return nil, fmt.Errorf("exclude: %w", err)
	}
	if settings.MaxReadBytes <= 0 || settings.MaxWriteBytes <= 0 {
		return nil, errors.New("byte limits must be positive")
	}
	if settings.MaxSearchResults <= 0 || settings.MaxFilesPerCall <= 0 {
		return nil, errors.New("result and file limits must be positive")
	}
	if isWrite(name) && !settings.AllowWrite {
		return nil, fmt.Errorf("%s requires allow_write=true", name)
	}
	if name == Delete && !settings.AllowDelete {
		return nil, errors.New("workspace.delete requires allow_delete=true")
	}
	return json.Marshal(settings)
}

func (Registration) IsSubset(name string, parent, child json.RawMessage) error {
	var p, c Settings
	if err := json.Unmarshal(parent, &p); err != nil {
		return fmt.Errorf("decode parent settings: %w", err)
	}
	if err := json.Unmarshal(child, &c); err != nil {
		return fmt.Errorf("decode child settings: %w", err)
	}
	if p.Root != c.Root {
		return errors.New("child workspace root must equal parent root")
	}
	if err := subsetGlobs(p.ReadAllow, c.ReadAllow, "read_allow"); err != nil {
		return err
	}
	if err := subsetGlobs(p.WriteAllow, c.WriteAllow, "write_allow"); err != nil {
		return err
	}
	for _, excluded := range p.Exclude {
		if !slices.Contains(c.Exclude, excluded) {
			return fmt.Errorf("child removed parent exclusion %q", excluded)
		}
	}
	if !p.AllowWrite && c.AllowWrite || !p.AllowDelete && c.AllowDelete || !p.FollowSymlinks && c.FollowSymlinks {
		return errors.New("child workspace permissions widen parent permissions")
	}
	if p.RequireApproval && !c.RequireApproval {
		return errors.New("child cannot disable required approval")
	}
	if c.MaxReadBytes > p.MaxReadBytes || c.MaxWriteBytes > p.MaxWriteBytes ||
		c.MaxSearchResults > p.MaxSearchResults || c.MaxFilesPerCall > p.MaxFilesPerCall {
		return errors.New("child workspace limits exceed parent limits")
	}
	return nil
}

func (Registration) Configure(_ context.Context, name string, raw json.RawMessage, _ registry.Services, config *builtin.Config) error {
	normalized, err := (Registration{}).Normalize(name, raw)
	if err != nil {
		return err
	}
	var settings Settings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		return err
	}
	handler := &Handler{name: name, settings: settings}
	config.Handlers = append(config.Handlers, handler)
	config.Capabilities = append(config.Capabilities, capability(name, settings))
	return nil
}

type Handler struct {
	name     string
	settings Settings
}

func (h *Handler) Handles(name string) bool { return name == h.name }

func (h *Handler) DispatchCall(ctx context.Context, call dispatcher.Call) (dispatcher.Outcome, error) {
	if h.settings.RequireApproval {
		if resolved, ok := resolution.FromContext(ctx); !ok || resolved.Decision != resolution.Approved {
			return dispatcher.Yield("Approve " + call.Name + " inside " + h.settings.Root), nil
		}
	}
	var value any
	var err error
	switch call.Name {
	case List:
		value, err = h.list(call.Args)
	case Stat:
		value, err = h.stat(call.Args)
	case Read:
		value, err = h.read(call.Args)
	case Search:
		value, err = h.search(ctx, call.Args)
	case Write:
		value, err = h.write(call.Args)
	case Patch:
		value, err = h.patch(call.Args)
	case Mkdir:
		value, err = h.mkdir(call.Args)
	case Move:
		value, err = h.move(call.Args)
	case Delete:
		value, err = h.delete(call.Args)
	default:
		return dispatcher.Failed("unknown workspace call: " + call.Name), nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return dispatcher.Outcome{}, ctx.Err()
		}
		return dispatcher.Failed(err.Error()), nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return dispatcher.Outcome{}, err
	}
	return dispatcher.Result(raw), nil
}

type pathRequest struct {
	Path string `json:"path"`
}

type listRequest struct {
	Path      string `json:"path,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

type writeRequest struct {
	Path         string `json:"path"`
	Content      string `json:"content"`
	ExpectedHash string `json:"expected_hash,omitempty"`
	CreateOnly   bool   `json:"create_only,omitempty"`
}

type replaceEdit struct {
	Old string `json:"old"`
	New string `json:"new"`
	All bool   `json:"all,omitempty"`
}

type patchRequest struct {
	Path         string        `json:"path"`
	ExpectedHash string        `json:"expected_hash"`
	Edits        []replaceEdit `json:"edits"`
}

type moveRequest struct {
	From         string `json:"from"`
	To           string `json:"to"`
	ExpectedHash string `json:"expected_hash,omitempty"`
}

type searchRequest struct {
	Query         string `json:"query"`
	Path          string `json:"path,omitempty"`
	Regex         bool   `json:"regex,omitempty"`
	CaseSensitive bool   `json:"case_sensitive,omitempty"`
}

func (h *Handler) list(raw json.RawMessage) (any, error) {
	var req listRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	base, rel, err := h.resolve(req.Path, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(base)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory")
	}
	type entry struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
		Size int64  `json:"size,omitempty"`
	}
	result := make([]entry, 0)
	err = filepath.WalkDir(base, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == base {
			return nil
		}
		itemRel, _ := filepath.Rel(h.settings.Root, path)
		itemRel = filepath.ToSlash(itemRel)
		if h.excluded(itemRel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !h.allowed(itemRel, false) {
			if d.IsDir() {
				return nil
			}
			return nil
		}
		if !req.Recursive && filepath.Dir(itemRel) != filepath.ToSlash(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		kind := "file"
		if d.IsDir() {
			kind = "directory"
		} else if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		result = append(result, entry{Path: itemRel, Kind: kind, Size: info.Size()})
		if len(result) >= h.settings.MaxFilesPerCall {
			return io.EOF
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return map[string]any{"entries": result, "truncated": len(result) >= h.settings.MaxFilesPerCall}, nil
}

func (h *Handler) stat(raw json.RawMessage) (any, error) {
	var req pathRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	path, rel, err := h.resolve(req.Path, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"path": rel, "size": info.Size(), "mode": info.Mode().String(),
		"modified_at": info.ModTime().UTC(),
	}
	switch {
	case info.IsDir():
		result["kind"] = "directory"
	case info.Mode()&os.ModeSymlink != 0:
		result["kind"] = "symlink"
	default:
		result["kind"] = "file"
		if info.Mode().IsRegular() && info.Size() <= h.settings.MaxReadBytes {
			hash, _ := fileHash(path)
			result["hash"] = hash
		}
	}
	return result, nil
}

func (h *Handler) read(raw json.RawMessage) (any, error) {
	var req pathRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	path, rel, err := h.resolve(req.Path, false)
	if err != nil {
		return nil, err
	}
	data, err := readBounded(path, h.settings.MaxReadBytes)
	if err != nil {
		return nil, err
	}
	return map[string]any{"path": rel, "content": string(data), "hash": hashBytes(data), "bytes": len(data)}, nil
}

func (h *Handler) search(ctx context.Context, raw json.RawMessage) (any, error) {
	var req searchRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	if req.Query == "" {
		return nil, errors.New("query is required")
	}
	base, _, err := h.resolve(req.Path, false)
	if err != nil {
		return nil, err
	}
	var matcher func(string) bool
	if req.Regex {
		expr := req.Query
		if !req.CaseSensitive {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
		matcher = re.MatchString
	} else {
		needle := req.Query
		if !req.CaseSensitive {
			needle = strings.ToLower(needle)
		}
		matcher = func(line string) bool {
			if !req.CaseSensitive {
				line = strings.ToLower(line)
			}
			return strings.Contains(line, needle)
		}
	}
	type match struct {
		Path string `json:"path"`
		Line int    `json:"line"`
		Text string `json:"text"`
	}
	matches := make([]match, 0)
	err = filepath.WalkDir(base, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, _ := filepath.Rel(h.settings.Root, path)
		rel = filepath.ToSlash(rel)
		if h.excluded(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !h.allowed(rel, false) {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > h.settings.MaxReadBytes {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if matcher(line) {
				matches = append(matches, match{Path: rel, Line: i + 1, Text: truncate(line, 500)})
				if len(matches) >= h.settings.MaxSearchResults {
					return io.EOF
				}
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return map[string]any{"matches": matches, "truncated": len(matches) >= h.settings.MaxSearchResults}, nil
}

func (h *Handler) write(raw json.RawMessage) (any, error) {
	var req writeRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	if int64(len(req.Content)) > h.settings.MaxWriteBytes {
		return nil, errors.New("content exceeds max_write_bytes")
	}
	path, rel, err := h.resolve(req.Path, true)
	if err != nil {
		return nil, err
	}
	if err := verifyExpected(path, req.ExpectedHash, req.CreateOnly); err != nil {
		return nil, err
	}
	if err := atomicWrite(path, []byte(req.Content), 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"path": rel, "hash": hashBytes([]byte(req.Content)), "bytes": len(req.Content)}, nil
}

func (h *Handler) patch(raw json.RawMessage) (any, error) {
	var req patchRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	if req.ExpectedHash == "" || len(req.Edits) == 0 {
		return nil, errors.New("expected_hash and edits are required")
	}
	path, rel, err := h.resolve(req.Path, true)
	if err != nil {
		return nil, err
	}
	data, err := readBounded(path, h.settings.MaxWriteBytes)
	if err != nil {
		return nil, err
	}
	if hashBytes(data) != req.ExpectedHash {
		return nil, errors.New("content hash conflict")
	}
	content := string(data)
	for i, edit := range req.Edits {
		if edit.Old == "" {
			return nil, fmt.Errorf("edit %d old text is empty", i)
		}
		count := strings.Count(content, edit.Old)
		if count == 0 {
			return nil, fmt.Errorf("edit %d old text was not found", i)
		}
		if !edit.All && count != 1 {
			return nil, fmt.Errorf("edit %d matched %d times", i, count)
		}
		n := 1
		if edit.All {
			n = -1
		}
		content = strings.Replace(content, edit.Old, edit.New, n)
		if int64(len(content)) > h.settings.MaxWriteBytes {
			return nil, errors.New("patched content exceeds max_write_bytes")
		}
	}
	if err := atomicWrite(path, []byte(content), 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"path": rel, "hash": hashBytes([]byte(content)), "bytes": len(content)}, nil
}

func (h *Handler) mkdir(raw json.RawMessage) (any, error) {
	var req pathRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	path, rel, err := h.resolve(req.Path, true)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return map[string]any{"path": rel, "created": true}, nil
}

func (h *Handler) move(raw json.RawMessage) (any, error) {
	var req moveRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	from, fromRel, err := h.resolve(req.From, true)
	if err != nil {
		return nil, err
	}
	to, toRel, err := h.resolve(req.To, true)
	if err != nil {
		return nil, err
	}
	if req.ExpectedHash != "" {
		hash, err := fileHash(from)
		if err != nil {
			return nil, err
		}
		if hash != req.ExpectedHash {
			return nil, errors.New("content hash conflict")
		}
	}
	if _, err := os.Lstat(to); err == nil {
		return nil, errors.New("destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return nil, err
	}
	if err := os.Rename(from, to); err != nil {
		return nil, err
	}
	return map[string]any{"from": fromRel, "to": toRel}, nil
}

func (h *Handler) delete(raw json.RawMessage) (any, error) {
	var req writeRequest
	if err := decodeStrict(raw, &req); err != nil {
		return nil, err
	}
	path, rel, err := h.resolve(req.Path, true)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("directory deletion is not supported")
	}
	if err := verifyExpected(path, req.ExpectedHash, false); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return map[string]any{"path": rel, "deleted": true}, nil
}

func (h *Handler) resolve(input string, write bool) (string, string, error) {
	if input == "" {
		input = "."
	}
	if filepath.IsAbs(input) {
		return "", "", errors.New("absolute paths are not allowed")
	}
	clean := filepath.Clean(input)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", "", errors.New("path escapes workspace")
	}
	full := filepath.Join(h.settings.Root, clean)
	rel, err := filepath.Rel(h.settings.Root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", errors.New("path escapes workspace")
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		rel = ""
	}
	if h.excluded(rel) || !h.allowed(rel, write) {
		return "", "", fmt.Errorf("path %q is not allowed", rel)
	}
	check := full
	if write {
		check = filepath.Dir(full)
	}
	if !h.settings.FollowSymlinks {
		if err := rejectSymlinks(h.settings.Root, check); err != nil {
			return "", "", err
		}
	} else {
		existing := check
		for {
			if _, err := os.Lstat(existing); err == nil {
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", "", err
			}
			parent := filepath.Dir(existing)
			if parent == existing {
				return "", "", errors.New("cannot resolve workspace path")
			}
			existing = parent
		}
		resolved, err := filepath.EvalSymlinks(existing)
		if err != nil {
			return "", "", err
		}
		if !insideRoot(h.settings.Root, resolved) {
			return "", "", errors.New("symlink escapes workspace")
		}
	}
	return full, rel, nil
}

func (h *Handler) allowed(path string, write bool) bool {
	globs := h.settings.ReadAllow
	if write {
		globs = h.settings.WriteAllow
	}
	return matchesAny(path, globs)
}

func (h *Handler) excluded(path string) bool { return matchesAny(path, h.settings.Exclude) }

func capability(name string, settings Settings) dispatcher.Capability {
	descriptions := map[string]string{
		List:   "List bounded files and directories inside the configured workspace.",
		Stat:   "Inspect metadata and content hash for a workspace path.",
		Read:   "Read a bounded UTF-8 or text file inside the workspace.",
		Search: "Search bounded workspace text files using literal text or a regular expression.",
		Write:  "Atomically create or replace a workspace file with optional optimistic concurrency.",
		Patch:  "Apply exact text replacements to a workspace file using an expected content hash.",
		Mkdir:  "Create a directory inside the workspace.",
		Move:   "Move a file or directory inside the workspace.",
		Delete: "Delete one non-directory workspace file with optional optimistic concurrency.",
	}
	schemas := map[string]string{
		List:   `{"type":"object","properties":{"path":{"type":"string"},"recursive":{"type":"boolean"}},"additionalProperties":false}`,
		Stat:   `{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`,
		Read:   `{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`,
		Search: `{"type":"object","properties":{"query":{"type":"string"},"path":{"type":"string"},"regex":{"type":"boolean"},"case_sensitive":{"type":"boolean"}},"required":["query"],"additionalProperties":false}`,
		Write:  `{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"},"expected_hash":{"type":"string"},"create_only":{"type":"boolean"}},"required":["path","content"],"additionalProperties":false}`,
		Patch:  `{"type":"object","properties":{"path":{"type":"string"},"expected_hash":{"type":"string"},"edits":{"type":"array","items":{"type":"object","properties":{"old":{"type":"string"},"new":{"type":"string"},"all":{"type":"boolean"}},"required":["old","new"],"additionalProperties":false}},"required":["path","expected_hash","edits"],"additionalProperties":false}`,
		Mkdir:  `{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`,
		Move:   `{"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"},"expected_hash":{"type":"string"}},"required":["from","to"],"additionalProperties":false}`,
		Delete: `{"type":"object","properties":{"path":{"type":"string"},"expected_hash":{"type":"string"}},"required":["path"],"additionalProperties":false}`,
	}
	return dispatcher.Capability{
		Name: name, Description: descriptions[name] + " Root: " + settings.Root,
		InputSchema: json.RawMessage(schemas[name]),
	}
}

func isWrite(name string) bool {
	return name == Write || name == Patch || name == Mkdir || name == Move || name == Delete
}

func canonicalRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("workspace root: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("workspace root is not a directory")
	}
	return filepath.Clean(abs), nil
}

func decodeStrict(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("settings contain trailing JSON")
	}
	return nil
}

func normalizeGlobs(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(filepath.ToSlash(value))
		if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
			return nil, fmt.Errorf("invalid glob %q", value)
		}
		if _, err := filepath.Match(strings.ReplaceAll(value, "**", "*"), "probe"); err != nil {
			return nil, err
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return result, nil
}

func subsetGlobs(parent, child []string, field string) error {
	for _, candidate := range child {
		if !matchesAny(candidate, parent) && !slices.Contains(parent, candidate) {
			return fmt.Errorf("child %s entry %q is not permitted by parent", field, candidate)
		}
	}
	return nil
}

func matchesAny(path string, patterns []string) bool {
	path = filepath.ToSlash(path)
	for _, pattern := range patterns {
		if pattern == "**" || pattern == "*" {
			return true
		}
		if ok, _ := filepath.Match(pattern, path); ok {
			return true
		}
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "**")
			if strings.HasPrefix(path, prefix) || path == strings.TrimSuffix(prefix, "/") {
				return true
			}
		}
	}
	return false
}

func rejectSymlinks(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink traversal is disabled: %s", current)
		}
	}
	return nil
}

func insideRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds byte limit %d", limit)
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func verifyExpected(path, expected string, createOnly bool) error {
	hash, err := fileHash(path)
	if errors.Is(err, os.ErrNotExist) {
		if expected != "" {
			return errors.New("content hash conflict: file does not exist")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if createOnly {
		return errors.New("file already exists")
	}
	if expected != "" && expected != hash {
		return errors.New("content hash conflict")
	}
	return nil
}

func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func atomicWrite(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".aurora-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "…"
}

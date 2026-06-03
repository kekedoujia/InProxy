package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Route maps a public path prefix to an internal backend service.
type Route struct {
	Prefix        string `json:"prefix"`         // public prefix, e.g. "serviceA" (no leading slash)
	Target        string `json:"target"`         // backend address, e.g. "http://10.8.0.5:8080"
	StripPrefix   bool   `json:"strip_prefix"`   // whether to strip /prefix when forwarding
	Description   string `json:"description"`    // notes
	Enabled       bool   `json:"enabled"`        // whether the route is active
	MaxConcurrent int    `json:"max_concurrent"` // max simultaneous forwarded requests (0 = unlimited)
}

// Forward is a raw TCP port forward: a public listen port whose connections are
// piped to an internal host:port. Unlike Route (HTTP), this is L4 — it carries
// any TCP protocol (SSH, RDP, databases, ...).
type Forward struct {
	Name        string `json:"name"`        // unique identifier
	Listen      string `json:"listen"`      // external listen addr, e.g. ":2222" or "0.0.0.0:2222"
	Target      string `json:"target"`      // internal host:port, e.g. "10.8.0.5:22"
	Description string `json:"description"` // notes
	Enabled     bool   `json:"enabled"`     // whether the forward is active
}

// configFile is the on-disk shape. The first release stored a bare JSON array of
// routes; loadConfig still accepts that and migrates it into this object.
type configFile struct {
	Routes   []Route   `json:"routes"`
	Forwards []Forward `json:"forwards"`
}

// compiledRoute is a runtime route with its prebuilt reverse proxy.
type compiledRoute struct {
	Route
	proxy   *httputil.ReverseProxy
	limiter chan struct{} // semaphore capping in-flight requests; nil means unlimited
}

// prefixPattern restricts a prefix to safe URL path characters.
var prefixPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// reserved prefixes may not be claimed by business routes (admin / health).
var reserved = map[string]bool{"_admin": true, "_healthz": true}

// Store holds all routes in a thread-safe way and persists them to a JSON file.
type Store struct {
	mu        sync.RWMutex
	path      string
	routes    []Route
	forwards  []Forward
	compiled  []compiledRoute          // sorted by prefix length descending for longest-match
	onForward func(forwards []Forward) // notified after forwards change (set by main)
}

// NewStore loads the config from disk (creating an empty one if missing).
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.routes, s.forwards = []Route{}, []Forward{}
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	} else if len(data) > 0 {
		routes, forwards, err := parseConfig(data)
		if err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		s.routes, s.forwards = routes, forwards
	}
	if err := s.recompileLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// parseConfig accepts both the current object form {routes,forwards} and the
// original bare-array-of-routes form, migrating the latter transparently.
func parseConfig(data []byte) ([]Route, []Forward, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") { // legacy: bare array of routes
		var routes []Route
		if err := json.Unmarshal(data, &routes); err != nil {
			return nil, nil, err
		}
		return routes, []Forward{}, nil
	}
	var cf configFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, nil, err
	}
	if cf.Routes == nil {
		cf.Routes = []Route{}
	}
	if cf.Forwards == nil {
		cf.Forwards = []Forward{}
	}
	return cf.Routes, cf.Forwards, nil
}

// SetForwardListener registers a callback invoked (outside the lock) whenever the
// set of forwards changes, so the runtime forwarder can reconcile its listeners.
func (s *Store) SetForwardListener(fn func([]Forward)) {
	s.mu.Lock()
	s.onForward = fn
	s.mu.Unlock()
}

// List returns a copy of the routes.
func (s *Store) List() []Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Route, len(s.routes))
	copy(out, s.routes)
	return out
}

// Match returns the enabled route with the longest matching prefix.
func (s *Store) Match(path string) (*compiledRoute, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.compiled {
		c := &s.compiled[i]
		p := "/" + c.Prefix
		if path == p || strings.HasPrefix(path, p+"/") {
			return c, true
		}
	}
	return nil, false
}

// Upsert adds or updates a route (unique by prefix). Empty oldPrefix means add.
func (s *Store) Upsert(oldPrefix string, r Route) error {
	if err := validate(r); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i, existing := range s.routes {
		if existing.Prefix == r.Prefix {
			idx = i
		}
	}
	if oldPrefix == "" { // add
		if idx >= 0 {
			return fmt.Errorf("prefix %q already exists", r.Prefix)
		}
		s.routes = append(s.routes, r)
	} else { // update
		// when the prefix changed, make sure the new one does not collide
		if oldPrefix != r.Prefix && idx >= 0 {
			return fmt.Errorf("prefix %q already exists", r.Prefix)
		}
		found := false
		for i := range s.routes {
			if s.routes[i].Prefix == oldPrefix {
				s.routes[i] = r
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("prefix %q to update does not exist", oldPrefix)
		}
	}
	return s.commitLocked()
}

// Delete removes a route.
func (s *Store) Delete(prefix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.routes[:0]
	removed := false
	for _, r := range s.routes {
		if r.Prefix == prefix {
			removed = true
			continue
		}
		out = append(out, r)
	}
	if !removed {
		return fmt.Errorf("prefix %q does not exist", prefix)
	}
	s.routes = out
	return s.commitLocked()
}

func validate(r Route) error {
	if !prefixPattern.MatchString(r.Prefix) {
		return errors.New("prefix may contain only letters, digits, underscore and hyphen, and must start with a letter or digit")
	}
	if reserved[r.Prefix] {
		return fmt.Errorf("prefix %q is reserved and cannot be used", r.Prefix)
	}
	u, err := url.Parse(r.Target)
	if err != nil {
		return fmt.Errorf("invalid backend address: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("backend address must start with http:// or https://")
	}
	if u.Host == "" {
		return errors.New("backend address is missing host/port")
	}
	if r.MaxConcurrent < 0 {
		return errors.New("max concurrency must be a non-negative integer (0 = unlimited)")
	}
	return nil
}

// commitLocked recompiles and persists; the caller must hold the write lock.
func (s *Store) commitLocked() error {
	if err := s.recompileLocked(); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Store) recompileLocked() error {
	compiled := make([]compiledRoute, 0, len(s.routes))
	for _, r := range s.routes {
		if !r.Enabled {
			continue
		}
		p, err := buildProxy(r)
		if err != nil {
			return fmt.Errorf("route %q: %w", r.Prefix, err)
		}
		cr := compiledRoute{Route: r, proxy: p}
		if r.MaxConcurrent > 0 {
			cr.limiter = make(chan struct{}, r.MaxConcurrent)
		}
		compiled = append(compiled, cr)
	}
	// longest prefix first, so /a does not steal requests meant for /ab
	sort.SliceStable(compiled, func(i, j int) bool {
		return len(compiled[i].Prefix) > len(compiled[j].Prefix)
	})
	s.compiled = compiled
	return nil
}

func (s *Store) persistLocked() error {
	routes, forwards := s.routes, s.forwards
	if routes == nil {
		routes = []Route{}
	}
	if forwards == nil {
		forwards = []Forward{}
	}
	data, err := json.MarshalIndent(configFile{Routes: routes, Forwards: forwards}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return os.Rename(tmp, s.path) // atomic replace
}

// ---------- Forwards (TCP port forwarding) ----------

// ListForwards returns a copy of the configured forwards.
func (s *Store) ListForwards() []Forward {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Forward, len(s.forwards))
	copy(out, s.forwards)
	return out
}

// UpsertForward adds or updates a forward (unique by name). Empty oldName = add.
func (s *Store) UpsertForward(oldName string, f Forward) error {
	if err := validateForward(&f); err != nil {
		return err
	}
	s.mu.Lock()
	idx := -1
	for i, e := range s.forwards {
		if e.Name == f.Name {
			idx = i
		}
	}
	// no two forwards may bind the same listen address
	for _, e := range s.forwards {
		if e.Name != f.Name && e.Listen == f.Listen {
			s.mu.Unlock()
			return fmt.Errorf("listen address %q is already used by forward %q", f.Listen, e.Name)
		}
	}
	if oldName == "" { // add
		if idx >= 0 {
			s.mu.Unlock()
			return fmt.Errorf("forward %q already exists", f.Name)
		}
		s.forwards = append(s.forwards, f)
	} else { // update
		if oldName != f.Name && idx >= 0 {
			s.mu.Unlock()
			return fmt.Errorf("forward %q already exists", f.Name)
		}
		found := false
		for i := range s.forwards {
			if s.forwards[i].Name == oldName {
				s.forwards[i] = f
				found = true
				break
			}
		}
		if !found {
			s.mu.Unlock()
			return fmt.Errorf("forward %q to update does not exist", oldName)
		}
	}
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	s.fireForwards()
	return nil
}

// DeleteForward removes a forward by name.
func (s *Store) DeleteForward(name string) error {
	s.mu.Lock()
	out := s.forwards[:0]
	removed := false
	for _, f := range s.forwards {
		if f.Name == name {
			removed = true
			continue
		}
		out = append(out, f)
	}
	if !removed {
		s.mu.Unlock()
		return fmt.Errorf("forward %q does not exist", name)
	}
	s.forwards = out
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	s.fireForwards()
	return nil
}

// fireForwards notifies the registered listener with a snapshot of the forwards.
func (s *Store) fireForwards() {
	s.mu.RLock()
	fn := s.onForward
	snap := make([]Forward, len(s.forwards))
	copy(snap, s.forwards)
	s.mu.RUnlock()
	if fn != nil {
		fn(snap)
	}
}

// validateForward checks and normalizes a forward in place.
func validateForward(f *Forward) error {
	f.Name = strings.TrimSpace(f.Name)
	if !prefixPattern.MatchString(f.Name) {
		return errors.New("name may contain only letters, digits, underscore and hyphen, and must start with a letter or digit")
	}
	listen, err := normalizeListen(f.Listen)
	if err != nil {
		return err
	}
	f.Listen = listen
	target, err := normalizeHostPort(strings.TrimSpace(f.Target), false)
	if err != nil {
		return fmt.Errorf("internal target: %w", err)
	}
	f.Target = target
	f.Description = strings.TrimSpace(f.Description)
	return nil
}

// normalizeListen accepts "2222", ":2222", "0.0.0.0:2222" or "10.8.0.1:2222"
// and returns a canonical "host:port" (empty host = all interfaces).
func normalizeListen(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("external listen port is required")
	}
	if !strings.Contains(s, ":") { // bare port -> all interfaces
		s = ":" + s
	}
	return normalizeHostPort(s, true)
}

// normalizeHostPort validates a host:port. allowEmptyHost permits ":port" (bind
// all interfaces); otherwise a host is required (a forward target).
func normalizeHostPort(s string, allowEmptyHost bool) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("must be host:port (%v)", err)
	}
	if host == "" && !allowEmptyHost {
		return "", errors.New("missing host")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}

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

// DNATRule is a kernel destination-NAT mapping: connections arriving on a public
// port are rewritten (in iptables' nat table) to an internal host:port. Unlike
// Forward (a userspace TCP relay) this happens in the kernel, supports UDP, and
// can preserve the client's source IP (when SNAT is off).
type DNATRule struct {
	Name        string `json:"name"`        // unique identifier
	Proto       string `json:"proto"`       // "tcp" | "udp"
	ListenPort  int    `json:"listen_port"` // public port to match
	Target      string `json:"target"`      // internal host:port, e.g. "10.8.0.60:8765"
	SNAT        bool   `json:"snat"`        // masquerade return path (needed when the target won't route replies back through this host)
	Description string `json:"description"` // notes
	Enabled     bool   `json:"enabled"`     // whether the rule is active
}

// VHost maps a whole public hostname to one backend, served at the root path.
// TLS is terminated at inproxy (Let's Encrypt cert for Host in "auto" mode) and
// the request is reverse-proxied to Target; SkipVerify allows a self-signed
// internal backend over https.
type VHost struct {
	Host        string `json:"host"`        // public FQDN, e.g. "aperturemail.aperture-x.com"
	Target      string `json:"target"`      // backend, e.g. "https://10.8.0.60:18443"
	SkipVerify  bool   `json:"skip_verify"` // don't verify the backend's TLS cert (self-signed internal service)
	Description string `json:"description"` // notes
	Enabled     bool   `json:"enabled"`     // whether the vhost is active
}

// compiledVHost is a runtime vhost with its prebuilt reverse proxy.
type compiledVHost struct {
	VHost
	proxy *httputil.ReverseProxy
}

// configFile is the on-disk shape. The first release stored a bare JSON array of
// routes; loadConfig still accepts that and migrates it into this object.
type configFile struct {
	Routes   []Route    `json:"routes"`
	Forwards []Forward  `json:"forwards"`
	DNAT     []DNATRule `json:"dnat"`
	VHosts   []VHost    `json:"vhosts"`
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
	mu         sync.RWMutex
	path       string
	routes     []Route
	forwards   []Forward
	dnat       []DNATRule
	vhosts     []VHost
	compiled   []compiledRoute           // sorted by prefix length descending for longest-match
	compiledVH map[string]*compiledVHost // by lower-cased host
	onForward  func(forwards []Forward)  // notified after forwards change (set by main)
	onDNAT     func(rules []DNATRule)    // notified after DNAT rules change (set by main)
}

// NewStore loads the config from disk (creating an empty one if missing).
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.routes, s.forwards, s.dnat, s.vhosts = []Route{}, []Forward{}, []DNATRule{}, []VHost{}
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	} else if len(data) > 0 {
		routes, forwards, dnat, vhosts, err := parseConfig(data)
		if err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		s.routes, s.forwards, s.dnat, s.vhosts = routes, forwards, dnat, vhosts
	}
	if err := s.recompileLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// parseConfig accepts both the current object form {routes,forwards} and the
// original bare-array-of-routes form, migrating the latter transparently.
func parseConfig(data []byte) ([]Route, []Forward, []DNATRule, []VHost, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") { // legacy: bare array of routes
		var routes []Route
		if err := json.Unmarshal(data, &routes); err != nil {
			return nil, nil, nil, nil, err
		}
		return routes, []Forward{}, []DNATRule{}, []VHost{}, nil
	}
	var cf configFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, nil, nil, nil, err
	}
	if cf.Routes == nil {
		cf.Routes = []Route{}
	}
	if cf.Forwards == nil {
		cf.Forwards = []Forward{}
	}
	if cf.DNAT == nil {
		cf.DNAT = []DNATRule{}
	}
	if cf.VHosts == nil {
		cf.VHosts = []VHost{}
	}
	return cf.Routes, cf.Forwards, cf.DNAT, cf.VHosts, nil
}

// SetDNATListener registers a callback invoked (outside the lock) whenever the
// set of DNAT rules changes, so the runtime manager can reconcile iptables.
func (s *Store) SetDNATListener(fn func([]DNATRule)) {
	s.mu.Lock()
	s.onDNAT = fn
	s.mu.Unlock()
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

	vh := make(map[string]*compiledVHost)
	for _, v := range s.vhosts {
		if !v.Enabled {
			continue
		}
		p, err := buildVHostProxy(v)
		if err != nil {
			return fmt.Errorf("vhost %q: %w", v.Host, err)
		}
		cv := compiledVHost{VHost: v, proxy: p}
		vh[strings.ToLower(v.Host)] = &cv
	}
	s.compiledVH = vh
	return nil
}

// MatchVHost returns the enabled vhost serving host (case-insensitive), if any.
func (s *Store) MatchVHost(host string) (*compiledVHost, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cv, ok := s.compiledVH[strings.ToLower(host)]
	return cv, ok
}

// HasVHost reports whether an enabled vhost is configured for host. Used by the
// ACME host policy to decide which names to obtain certificates for.
func (s *Store) HasVHost(host string) bool {
	_, ok := s.MatchVHost(host)
	return ok
}

func (s *Store) persistLocked() error {
	routes, forwards, dnat, vhosts := s.routes, s.forwards, s.dnat, s.vhosts
	if routes == nil {
		routes = []Route{}
	}
	if forwards == nil {
		forwards = []Forward{}
	}
	if dnat == nil {
		dnat = []DNATRule{}
	}
	if vhosts == nil {
		vhosts = []VHost{}
	}
	data, err := json.MarshalIndent(configFile{Routes: routes, Forwards: forwards, DNAT: dnat, VHosts: vhosts}, "", "  ")
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

// ---------- DNAT rules (kernel destination NAT) ----------

// ListDNAT returns a copy of the configured DNAT rules.
func (s *Store) ListDNAT() []DNATRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DNATRule, len(s.dnat))
	copy(out, s.dnat)
	return out
}

// UpsertDNAT adds or updates a DNAT rule (unique by name). Empty oldName = add.
func (s *Store) UpsertDNAT(oldName string, d DNATRule) error {
	if err := validateDNAT(&d); err != nil {
		return err
	}
	s.mu.Lock()
	idx := -1
	for i, e := range s.dnat {
		if e.Name == d.Name {
			idx = i
		}
	}
	// no two rules may claim the same proto + public port
	for _, e := range s.dnat {
		if e.Name != d.Name && e.Proto == d.Proto && e.ListenPort == d.ListenPort {
			s.mu.Unlock()
			return fmt.Errorf("%s port %d is already used by rule %q", d.Proto, d.ListenPort, e.Name)
		}
	}
	if oldName == "" { // add
		if idx >= 0 {
			s.mu.Unlock()
			return fmt.Errorf("rule %q already exists", d.Name)
		}
		s.dnat = append(s.dnat, d)
	} else { // update
		if oldName != d.Name && idx >= 0 {
			s.mu.Unlock()
			return fmt.Errorf("rule %q already exists", d.Name)
		}
		found := false
		for i := range s.dnat {
			if s.dnat[i].Name == oldName {
				s.dnat[i] = d
				found = true
				break
			}
		}
		if !found {
			s.mu.Unlock()
			return fmt.Errorf("rule %q to update does not exist", oldName)
		}
	}
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	s.fireDNAT()
	return nil
}

// DeleteDNAT removes a DNAT rule by name.
func (s *Store) DeleteDNAT(name string) error {
	s.mu.Lock()
	out := s.dnat[:0]
	removed := false
	for _, d := range s.dnat {
		if d.Name == name {
			removed = true
			continue
		}
		out = append(out, d)
	}
	if !removed {
		s.mu.Unlock()
		return fmt.Errorf("rule %q does not exist", name)
	}
	s.dnat = out
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	s.fireDNAT()
	return nil
}

func (s *Store) fireDNAT() {
	s.mu.RLock()
	fn := s.onDNAT
	snap := make([]DNATRule, len(s.dnat))
	copy(snap, s.dnat)
	s.mu.RUnlock()
	if fn != nil {
		fn(snap)
	}
}

// validateDNAT checks and normalizes a DNAT rule in place.
func validateDNAT(d *DNATRule) error {
	d.Name = strings.TrimSpace(d.Name)
	if !prefixPattern.MatchString(d.Name) {
		return errors.New("name may contain only letters, digits, underscore and hyphen, and must start with a letter or digit")
	}
	d.Proto = strings.ToLower(strings.TrimSpace(d.Proto))
	if d.Proto != "tcp" && d.Proto != "udp" {
		return errors.New("protocol must be tcp or udp")
	}
	if d.ListenPort < 1 || d.ListenPort > 65535 {
		return errors.New("public port must be between 1 and 65535")
	}
	target, err := normalizeHostPort(strings.TrimSpace(d.Target), false)
	if err != nil {
		return fmt.Errorf("internal target: %w", err)
	}
	d.Target = target
	d.Description = strings.TrimSpace(d.Description)
	return nil
}

// ---------- VHosts (host-based reverse proxy) ----------

// hostPattern matches a plausible FQDN (at least one dot).
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// ListVHosts returns a copy of the configured vhosts.
func (s *Store) ListVHosts() []VHost {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]VHost, len(s.vhosts))
	copy(out, s.vhosts)
	return out
}

// UpsertVHost adds or updates a vhost (unique by host). Empty oldHost = add.
func (s *Store) UpsertVHost(oldHost string, v VHost) error {
	if err := validateVHost(&v); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, e := range s.vhosts {
		if strings.EqualFold(e.Host, v.Host) {
			idx = i
		}
	}
	if oldHost == "" { // add
		if idx >= 0 {
			return fmt.Errorf("host %q already exists", v.Host)
		}
		s.vhosts = append(s.vhosts, v)
	} else { // update
		if !strings.EqualFold(oldHost, v.Host) && idx >= 0 {
			return fmt.Errorf("host %q already exists", v.Host)
		}
		found := false
		for i := range s.vhosts {
			if strings.EqualFold(s.vhosts[i].Host, oldHost) {
				s.vhosts[i] = v
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("host %q to update does not exist", oldHost)
		}
	}
	return s.commitLocked()
}

// DeleteVHost removes a vhost by host.
func (s *Store) DeleteVHost(host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.vhosts[:0]
	removed := false
	for _, v := range s.vhosts {
		if strings.EqualFold(v.Host, host) {
			removed = true
			continue
		}
		out = append(out, v)
	}
	if !removed {
		return fmt.Errorf("host %q does not exist", host)
	}
	s.vhosts = out
	return s.commitLocked()
}

// validateVHost checks and normalizes a vhost in place.
func validateVHost(v *VHost) error {
	v.Host = strings.TrimSpace(strings.ToLower(v.Host))
	if !hostPattern.MatchString(v.Host) {
		return errors.New("host must be a valid domain name, e.g. mail.example.com")
	}
	u, err := url.Parse(strings.TrimSpace(v.Target))
	if err != nil {
		return fmt.Errorf("invalid backend address: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("backend address must start with http:// or https://")
	}
	if u.Host == "" {
		return errors.New("backend address is missing host/port")
	}
	v.Target = u.String()
	v.Description = strings.TrimSpace(v.Description)
	return nil
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

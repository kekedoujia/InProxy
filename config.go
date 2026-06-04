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

// Forward is a raw L4 port forward: a public listen port whose connections are
// piped to an internal host:port. Carries any TCP protocol (SSH, RDP, databases)
// or UDP datagrams (DNS, WireGuard, syslog, ...) depending on Proto.
type Forward struct {
	Name        string `json:"name"`        // unique identifier
	Proto       string `json:"proto"`       // "tcp" | "udp" (empty = tcp, legacy)
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

// PortForward is one public-port mapping under a Domain. When ManageCert is true,
// inproxy terminates TLS on Port with an automatic Let's Encrypt certificate and
// reverse-proxies to the backend; when false, inproxy passes the TLS connection
// through to the backend untouched (the backend presents its own certificate).
type PortForward struct {
	Port       int  `json:"port"`        // public port, e.g. 443
	Target     string `json:"target"`    // internal "ip:port", e.g. "10.8.0.60:18443"
	ManageCert bool `json:"manage_cert"` // true: terminate + Let's Encrypt; false: TLS passthrough
	BackendTLS bool `json:"backend_tls"` // terminate mode: backend speaks https (else http)
	SkipVerify bool `json:"skip_verify"` // terminate + backend_tls: skip backend cert verification
	Enabled    bool `json:"enabled"`     // whether this mapping is active
}

// Domain is one public hostname (matched by TLS SNI) with a set of per-port
// forwards under it.
type Domain struct {
	Host        string        `json:"host"`        // public FQDN, e.g. "aperturemail.aperture-x.com"
	Description string        `json:"description"` // notes
	Forwards    []PortForward `json:"forwards"`    // one per public port
}

// compiledPF is a runtime port-forward: the rule plus, for terminate mode, a
// prebuilt reverse proxy.
type compiledPF struct {
	Host string
	PortForward
	proxy *httputil.ReverseProxy // non-nil only in terminate (ManageCert) mode
}

// configFile is the on-disk shape. The first release stored a bare JSON array of
// routes; loadConfig still accepts that and migrates it into this object.
type configFile struct {
	Routes   []Route    `json:"routes"`
	Forwards []Forward  `json:"forwards"`
	DNAT     []DNATRule `json:"dnat"`
	Domains  []Domain   `json:"domains"`
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
	mu          sync.RWMutex
	path        string
	routes      []Route
	forwards    []Forward
	dnat        []DNATRule
	domains     []Domain
	compiled    []compiledRoute                // routes, longest prefix first
	compiledDom map[int]map[string]*compiledPF // port -> lower-cased host -> rule
	onForward   func(forwards []Forward)       // notified after forwards change (set by main)
	onDNAT      func(rules []DNATRule)         // notified after DNAT rules change (set by main)
	onDomain    func()                         // notified after domains change (set by main)
}

// NewStore loads the config from disk (creating an empty one if missing).
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.routes, s.forwards, s.dnat, s.domains = []Route{}, []Forward{}, []DNATRule{}, []Domain{}
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	} else if len(data) > 0 {
		routes, forwards, dnat, domains, err := parseConfig(data)
		if err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		s.routes, s.forwards, s.dnat, s.domains = routes, forwards, dnat, domains
	}
	if err := s.recompileLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// parseConfig accepts the object form, the original bare-array-of-routes form,
// and the intermediate form that had a flat "vhosts" list (migrated into the
// nested "domains" model: each old vhost becomes a domain with one 443 forward).
func parseConfig(data []byte) ([]Route, []Forward, []DNATRule, []Domain, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") { // legacy: bare array of routes
		var routes []Route
		if err := json.Unmarshal(data, &routes); err != nil {
			return nil, nil, nil, nil, err
		}
		return routes, []Forward{}, []DNATRule{}, []Domain{}, nil
	}
	var cf struct {
		Routes   []Route    `json:"routes"`
		Forwards []Forward  `json:"forwards"`
		DNAT     []DNATRule `json:"dnat"`
		Domains  []Domain   `json:"domains"`
		VHosts   []struct {
			Host        string `json:"host"`
			Target      string `json:"target"`
			SkipVerify  bool   `json:"skip_verify"`
			Description string `json:"description"`
			Enabled     bool   `json:"enabled"`
		} `json:"vhosts"`
	}
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, nil, nil, nil, err
	}
	domains := cf.Domains
	if domains == nil {
		domains = []Domain{}
	}
	for _, v := range cf.VHosts { // migrate legacy flat vhosts -> nested domains
		host, port := v.Target, "443"
		https := false
		if u, err := url.Parse(v.Target); err == nil && u.Host != "" {
			host = u.Host
			https = u.Scheme == "https"
		}
		domains = append(domains, Domain{
			Host:        v.Host,
			Description: v.Description,
			Forwards: []PortForward{{
				Port: 443, Target: host, ManageCert: true,
				BackendTLS: https, SkipVerify: v.SkipVerify, Enabled: v.Enabled,
			}},
		})
		_ = port
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
	return cf.Routes, cf.Forwards, cf.DNAT, domains, nil
}

// SetDNATListener registers a callback invoked (outside the lock) whenever the
// set of DNAT rules changes, so the runtime manager can reconcile iptables.
func (s *Store) SetDNATListener(fn func([]DNATRule)) {
	s.mu.Lock()
	s.onDNAT = fn
	s.mu.Unlock()
}

// SetDomainListener registers a callback invoked (outside the lock) whenever the
// set of domains changes, so the runtime router can reconcile its listeners.
func (s *Store) SetDomainListener(fn func()) {
	s.mu.Lock()
	s.onDomain = fn
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

	dom := make(map[int]map[string]*compiledPF)
	for _, d := range s.domains {
		for _, f := range d.Forwards {
			if !f.Enabled {
				continue
			}
			cp := &compiledPF{Host: d.Host, PortForward: f}
			switch {
			case f.Port == 80:
				// :80 is plaintext HTTP — always a reverse proxy to the backend (http)
				p, err := buildTerminateProxy(d.Host, PortForward{Target: f.Target})
				if err != nil {
					return fmt.Errorf("domain %q port 80: %w", d.Host, err)
				}
				cp.proxy = p
			case f.ManageCert:
				p, err := buildTerminateProxy(d.Host, f)
				if err != nil {
					return fmt.Errorf("domain %q port %d: %w", d.Host, f.Port, err)
				}
				cp.proxy = p
			}
			if dom[f.Port] == nil {
				dom[f.Port] = make(map[string]*compiledPF)
			}
			dom[f.Port][strings.ToLower(d.Host)] = cp
		}
	}
	s.compiledDom = dom
	return nil
}

// MatchDomain returns the enabled forward for (host, port), case-insensitive.
func (s *Store) MatchDomain(host string, port int) (*compiledPF, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.compiledDom[port]
	if m == nil {
		return nil, false
	}
	cp, ok := m[strings.ToLower(host)]
	return cp, ok
}

// IsTerminateHost reports whether host has an enabled terminate (manage-cert)
// forward on any port. Used by the ACME host policy to decide which names to
// obtain certificates for (passthrough hosts are excluded — the backend owns them).
func (s *Store) IsTerminateHost(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := strings.ToLower(host)
	for _, m := range s.compiledDom {
		if cp, ok := m[h]; ok && cp.ManageCert {
			return true
		}
	}
	return false
}

// DomainPorts returns every distinct enabled public port. The caller skips the
// main proxy port (which already has a listener) and opens the rest.
func (s *Store) DomainPorts() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ports []int
	for p := range s.compiledDom {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

func (s *Store) persistLocked() error {
	routes, forwards, dnat, domains := s.routes, s.forwards, s.dnat, s.domains
	if routes == nil {
		routes = []Route{}
	}
	if forwards == nil {
		forwards = []Forward{}
	}
	if dnat == nil {
		dnat = []DNATRule{}
	}
	if domains == nil {
		domains = []Domain{}
	}
	data, err := json.MarshalIndent(configFile{Routes: routes, Forwards: forwards, DNAT: dnat, Domains: domains}, "", "  ")
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
	// no two forwards may bind the same proto + listen address
	for _, e := range s.forwards {
		if e.Name != f.Name && e.Proto == f.Proto && e.Listen == f.Listen {
			s.mu.Unlock()
			return fmt.Errorf("%s listen address %q is already used by forward %q", f.Proto, f.Listen, e.Name)
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

// ---------- Domains (SNI-routed, per-port terminate or passthrough) ----------

// hostPattern matches a plausible FQDN (at least one dot).
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// ListDomains returns a copy of the configured domains.
func (s *Store) ListDomains() []Domain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Domain, len(s.domains))
	copy(out, s.domains)
	return out
}

// UpsertDomain adds or updates a domain and all its forwards (unique by host).
// Empty oldHost = add.
func (s *Store) UpsertDomain(oldHost string, d Domain) error {
	if err := validateDomain(&d); err != nil {
		return err
	}
	s.mu.Lock()
	idx := -1
	for i, e := range s.domains {
		if strings.EqualFold(e.Host, d.Host) {
			idx = i
		}
	}
	if oldHost == "" { // add
		if idx >= 0 {
			s.mu.Unlock()
			return fmt.Errorf("domain %q already exists", d.Host)
		}
		s.domains = append(s.domains, d)
	} else { // update
		if !strings.EqualFold(oldHost, d.Host) && idx >= 0 {
			s.mu.Unlock()
			return fmt.Errorf("domain %q already exists", d.Host)
		}
		found := false
		for i := range s.domains {
			if strings.EqualFold(s.domains[i].Host, oldHost) {
				s.domains[i] = d
				found = true
				break
			}
		}
		if !found {
			s.mu.Unlock()
			return fmt.Errorf("domain %q to update does not exist", oldHost)
		}
	}
	if err := s.commitLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	s.fireDomain()
	return nil
}

// DeleteDomain removes a domain (and all its forwards) by host.
func (s *Store) DeleteDomain(host string) error {
	s.mu.Lock()
	out := s.domains[:0]
	removed := false
	for _, d := range s.domains {
		if strings.EqualFold(d.Host, host) {
			removed = true
			continue
		}
		out = append(out, d)
	}
	if !removed {
		s.mu.Unlock()
		return fmt.Errorf("domain %q does not exist", host)
	}
	s.domains = out
	if err := s.commitLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	s.fireDomain()
	return nil
}

func (s *Store) fireDomain() {
	s.mu.RLock()
	fn := s.onDomain
	s.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

// validateDomain checks and normalizes a domain and its forwards in place.
func validateDomain(d *Domain) error {
	d.Host = strings.TrimSpace(strings.ToLower(d.Host))
	if !hostPattern.MatchString(d.Host) {
		return errors.New("host must be a valid domain name, e.g. mail.example.com")
	}
	d.Description = strings.TrimSpace(d.Description)
	if len(d.Forwards) == 0 {
		return errors.New("add at least one port forward")
	}
	seen := map[int]bool{}
	for i := range d.Forwards {
		f := &d.Forwards[i]
		if f.Port < 1 || f.Port > 65535 {
			return fmt.Errorf("public port must be between 1 and 65535 (got %d)", f.Port)
		}
		if f.Port == 80 {
			// :80 is always a plaintext HTTP reverse proxy; TLS settings don't apply
			f.ManageCert = false
			f.BackendTLS = false
			f.SkipVerify = false
		}
		if seen[f.Port] {
			return fmt.Errorf("duplicate public port %d for this domain", f.Port)
		}
		seen[f.Port] = true
		target, err := normalizeHostPort(strings.TrimSpace(f.Target), false)
		if err != nil {
			return fmt.Errorf("port %d target: %w", f.Port, err)
		}
		f.Target = target
		if !f.ManageCert {
			// passthrough: backend TLS settings are irrelevant
			f.BackendTLS = false
			f.SkipVerify = false
		}
	}
	return nil
}

// validateForward checks and normalizes a forward in place.
func validateForward(f *Forward) error {
	f.Name = strings.TrimSpace(f.Name)
	if !prefixPattern.MatchString(f.Name) {
		return errors.New("name may contain only letters, digits, underscore and hyphen, and must start with a letter or digit")
	}
	f.Proto = strings.ToLower(strings.TrimSpace(f.Proto))
	if f.Proto == "" {
		f.Proto = "tcp"
	}
	if f.Proto != "tcp" && f.Proto != "udp" && f.Proto != "tcp+udp" {
		return errors.New("protocol must be tcp, udp, or tcp+udp")
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

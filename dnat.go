package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// DNAT chain names: all of inproxy's kernel rules live in these dedicated nat
// chains so we never touch PREROUTING/POSTROUTING rules owned by others
// (OpenVPN's SNAT, Docker, etc.) — we only flush and rebuild our own chains.
const (
	dnatChain = "INPROXY_DNAT" // DNAT rules, hooked from nat PREROUTING
	postChain = "INPROXY_POST" // return-path MASQUERADE, hooked from nat POSTROUTING
)

// DNATManager reconciles the configured DNAT rules into iptables. It requires
// CAP_NET_ADMIN (granted by the systemd unit); it runs the iptables binary
// directly while staying non-root.
type DNATManager struct {
	mu      sync.Mutex
	ipt     string            // iptables binary path
	status  map[string]string // rule name -> "active" | "disabled" | "error: ..."
	lastErr string            // last scaffolding error, if any
}

// NewDNATManager locates the iptables binary.
func NewDNATManager() *DNATManager {
	ipt := "/usr/sbin/iptables"
	if p, err := exec.LookPath("iptables"); err == nil {
		ipt = p
	}
	return &DNATManager{ipt: ipt, status: map[string]string{}}
}

// Apply reconciles iptables to match the desired DNAT rules. Our two chains are
// flushed and rebuilt every time, so the result is exactly the enabled rules.
func (m *DNATManager) Apply(rules []DNATRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := make(map[string]string, len(rules))
	if err := m.ensureScaffolding(); err != nil {
		m.lastErr = err.Error()
		for _, r := range rules {
			if r.Enabled {
				status[r.Name] = "error: " + err.Error()
			} else {
				status[r.Name] = "disabled"
			}
		}
		m.status = status
		log.Printf("dnat: scaffolding failed: %v", err)
		return
	}
	m.lastErr = ""
	_, _ = m.run("-t", "nat", "-F", dnatChain)
	_, _ = m.run("-t", "nat", "-F", postChain)

	for _, r := range rules {
		if !r.Enabled {
			status[r.Name] = "disabled"
			continue
		}
		if err := m.applyRule(r); err != nil {
			status[r.Name] = "error: " + err.Error()
			log.Printf("dnat: rule %q failed: %v", r.Name, err)
			continue
		}
		status[r.Name] = "active"
		log.Printf("dnat: %s :%d -> %s (snat=%v)", r.Proto, r.ListenPort, r.Target, r.SNAT)
	}
	m.status = status
}

// applyRule appends the DNAT (and optional MASQUERADE) for one rule. The DNAT
// matches only traffic addressed to one of this host's own IPs (--dst-type
// LOCAL), so forwarded/transit traffic on the same port is never hijacked.
func (m *DNATManager) applyRule(r DNATRule) error {
	port := strconv.Itoa(r.ListenPort)
	if _, err := m.run("-t", "nat", "-A", dnatChain,
		"-p", r.Proto, "-m", "addrtype", "--dst-type", "LOCAL",
		"--dport", port, "-j", "DNAT", "--to-destination", r.Target); err != nil {
		return err
	}
	if r.SNAT {
		host, tport, err := net.SplitHostPort(r.Target)
		if err != nil {
			return err
		}
		if _, err := m.run("-t", "nat", "-A", postChain,
			"-p", r.Proto, "-d", host, "--dport", tport, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}
	return nil
}

// ensureScaffolding creates our chains and hooks them into the built-in chains,
// idempotently.
func (m *DNATManager) ensureScaffolding() error {
	_, _ = m.run("-t", "nat", "-N", dnatChain) // ignore "chain exists"
	_, _ = m.run("-t", "nat", "-N", postChain)
	if err := m.ensureJump("PREROUTING", dnatChain, "-I"); err != nil {
		return err
	}
	if err := m.ensureJump("POSTROUTING", postChain, "-A"); err != nil {
		return err
	}
	return nil
}

// ensureJump makes sure `parent -j target` exists, adding it with addFlag
// (-I to prepend, -A to append) only when absent.
func (m *DNATManager) ensureJump(parent, target, addFlag string) error {
	if _, err := m.run("-t", "nat", "-C", parent, "-j", target); err == nil {
		return nil
	}
	_, err := m.run("-t", "nat", addFlag, parent, "-j", target)
	return err
}

// Shutdown clears our rules so stopping inproxy stops the forwarding (the empty
// chains and hooks are left in place — cheap, and refilled on next start).
func (m *DNATManager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.run("-t", "nat", "-F", dnatChain)
	_, _ = m.run("-t", "nat", "-F", postChain)
}

// Status returns a snapshot of each rule's state plus the last global error.
func (m *DNATManager) Status() (map[string]string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.status))
	for k, v := range m.status {
		out[k] = v
	}
	return out, m.lastErr
}

func (m *DNATManager) run(args ...string) (string, error) {
	out, err := exec.Command(m.ipt, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("iptables %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

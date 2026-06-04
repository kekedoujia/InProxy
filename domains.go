package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Domain routing works at the TLS layer: peek the ClientHello SNI, then either
// pass the connection through untouched to the backend (manage-cert off, so the
// backend serves its own cert) or hand it to a TLS-terminating server (manage-cert
// on). Anything not matched falls through to the caller's default handling.

// sni decision actions.
const (
	actAccept      = iota // hand the connection to the wrapped consumer (TLS terminate / fallthrough)
	actPassthrough        // splice raw to the backend
	actDrop               // close the connection
)

type sniDecision struct {
	action int
	target string // backend "ip:port" for actPassthrough
}

// errPeeked aborts the throwaway handshake once the SNI has been captured.
var errPeeked = errors.New("peeked")

// peekConn records everything read (to replay later) and swallows writes (so the
// throwaway TLS handshake's alert never reaches the real client).
type peekConn struct {
	net.Conn
	recorded []byte
}

func (c *peekConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.recorded = append(c.recorded, p[:n]...)
	}
	return n, err
}

func (c *peekConn) Write(p []byte) (int, error) { return len(p), nil }

// prefixConn replays recorded bytes before reading from the underlying conn.
type prefixConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// peekClientHelloSNI reads the TLS ClientHello from c, returns its SNI and the
// exact bytes consumed (for replay). It never writes to c.
func peekClientHelloSNI(c net.Conn) (string, []byte) {
	pc := &peekConn{Conn: c}
	var sni string
	cfg := &tls.Config{GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = chi.ServerName
		return nil, errPeeked
	}}
	_ = tls.Server(pc, cfg).HandshakeContext(context.Background())
	return sni, pc.recorded
}

// sniListener wraps a raw TCP listener: it peeks SNI on each connection and routes
// per decide. Passthrough/drop are handled inline; only actAccept connections are
// returned from Accept (so an http.Server / tls.NewListener can consume them).
type sniListener struct {
	inner  net.Listener
	decide func(sni string) sniDecision
	ready  chan net.Conn
	done   chan struct{}
	once   sync.Once
}

func newSNIListener(inner net.Listener, decide func(string) sniDecision) *sniListener {
	l := &sniListener{inner: inner, decide: decide, ready: make(chan net.Conn), done: make(chan struct{})}
	go l.loop()
	return l
}

func (l *sniListener) loop() {
	defer l.once.Do(func() { close(l.done) })
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return
		}
		go l.handle(c)
	}
}

func (l *sniListener) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	sni, recorded := peekClientHelloSNI(c)
	_ = c.SetReadDeadline(time.Time{})
	switch d := l.decide(sni); d.action {
	case actPassthrough:
		spliceTo(c, recorded, d.target)
	case actDrop:
		_ = c.Close()
	default:
		pc := &prefixConn{Conn: c, prefix: recorded}
		select {
		case l.ready <- pc:
		case <-l.done:
			_ = c.Close()
		}
	}
}

func (l *sniListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *sniListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.inner.Close()
}

func (l *sniListener) Addr() net.Addr { return l.inner.Addr() }

// spliceTo pipes a passthrough connection to the backend, replaying the peeked
// ClientHello first so the TLS handshake completes end-to-end with the backend.
func spliceTo(client net.Conn, prefix []byte, backendAddr string) {
	defer client.Close()
	backend, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil {
		log.Printf("domain passthrough dial %s: %v", backendAddr, err)
		return
	}
	defer backend.Close()
	if len(prefix) > 0 {
		if _, err := backend.Write(prefix); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if t, ok := dst.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(backend, client)
	go cp(client, backend)
	<-done
	<-done
}

// DomainRouter runs the per-port listeners for domain forwards on ports other
// than 443 (443 is wrapped by the main proxy server). It reconciles listeners
// when the set of ports changes; per-connection routing is read live from the
// store, so adding/removing a rule on an existing port needs no restart.
type DomainRouter struct {
	mu       sync.Mutex
	store    *Store
	tlsConf  *tls.Config // autocert TLS config for terminate mode (nil disables terminate on extra ports)
	mainPort int         // the main HTTPS port, served elsewhere — never bound here
	httpPort int         // the :80 HTTP port, served elsewhere (plaintext domain proxy) — never bound here
	active   map[int]*portServer
}

type portServer struct {
	ln  *sniListener
	srv *http.Server
}

func NewDomainRouter(store *Store, tlsConf *tls.Config, mainPort, httpPort int) *DomainRouter {
	return &DomainRouter{store: store, tlsConf: tlsConf, mainPort: mainPort, httpPort: httpPort, active: map[int]*portServer{}}
}

// Apply reconciles the extra-port listeners to the configured domain ports.
func (r *DomainRouter) Apply() {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := map[int]bool{}
	for _, p := range r.store.DomainPorts() {
		if p != r.mainPort && p != r.httpPort {
			want[p] = true
		}
	}
	for p, ps := range r.active {
		if !want[p] {
			ps.stop()
			delete(r.active, p)
		}
	}
	for p := range want {
		if _, ok := r.active[p]; ok {
			continue
		}
		ps, err := r.startPort(p)
		if err != nil {
			log.Printf("domain port %d listen failed: %v", p, err)
			continue
		}
		r.active[p] = ps
	}
}

func (r *DomainRouter) startPort(p int) (*portServer, error) {
	raw, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
	if err != nil {
		return nil, err
	}
	decide := func(sni string) sniDecision {
		cp, ok := r.store.MatchDomain(sni, p)
		if !ok {
			return sniDecision{action: actDrop}
		}
		if cp.ManageCert {
			if r.tlsConf == nil {
				return sniDecision{action: actDrop} // can't terminate without a cert source
			}
			return sniDecision{action: actAccept}
		}
		return sniDecision{action: actPassthrough, target: cp.Target}
	}
	ln := newSNIListener(raw, decide)
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if cp, ok := r.store.MatchDomain(hostOnly(req.Host), p); ok && cp.ManageCert {
			cp.serve(w, req)
			return
		}
		http.NotFound(w, req)
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	var tlsLn net.Listener = ln
	if r.tlsConf != nil {
		tlsLn = tls.NewListener(ln, r.tlsConf)
	}
	go func() {
		if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			log.Printf("domain port %d server exited: %v", p, err)
		}
	}()
	log.Printf("domain port %d listening", p)
	return &portServer{ln: ln, srv: srv}, nil
}

func (ps *portServer) stop() {
	if ps.srv != nil {
		_ = ps.srv.Close()
	}
	_ = ps.ln.Close()
}

// Shutdown stops all extra-port listeners.
func (r *DomainRouter) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for p, ps := range r.active {
		ps.stop()
		delete(r.active, p)
	}
}

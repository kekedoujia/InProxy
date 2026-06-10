package main

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// udpSessionIdle is how long a UDP client→backend mapping is kept after the last
// packet before it is torn down.
const udpSessionIdle = 90 * time.Second

// Forwarder runs the live L4 port forwards (TCP relays and UDP datagram relays).
// It reconciles the set of desired Forward configs against the listeners actually
// open, starting/stopping as the admin edits them. Bind failures are recorded
// per-forward (surfaced in the UI) rather than aborting the whole apply.
type Forwarder struct {
	mu     sync.Mutex
	active map[string]*fwdListener // name -> running listener
	status map[string]string      // name -> "" (running) | "disabled" | "error: ..."
}

// NewForwarder returns an empty forwarder; call Apply to start listeners.
func NewForwarder() *Forwarder {
	return &Forwarder{active: map[string]*fwdListener{}, status: map[string]string{}}
}

// Apply reconciles the running listeners to match the desired forwards.
func (f *Forwarder) Apply(forwards []Forward) {
	f.mu.Lock()
	defer f.mu.Unlock()

	want := make(map[string]Forward, len(forwards))
	for _, fw := range forwards {
		want[fw.Name] = fw
	}
	// stop listeners that are gone, disabled, or whose proto/addr/target changed
	for name, l := range f.active {
		w, ok := want[name]
		if !ok || !w.Enabled || w.Proto != l.fwd.Proto || w.Listen != l.fwd.Listen || w.Target != l.fwd.Target || w.ProxyProto != l.fwd.ProxyProto {
			l.stop()
			delete(f.active, name)
		}
	}
	// (re)start everything that should be running
	status := make(map[string]string, len(forwards))
	for _, fw := range forwards {
		if !fw.Enabled {
			status[fw.Name] = "disabled"
			continue
		}
		if _, ok := f.active[fw.Name]; ok {
			status[fw.Name] = "" // already running with the same config
			continue
		}
		l, err := startListener(fw)
		if err != nil {
			status[fw.Name] = "error: " + err.Error()
			log.Printf("forward %q listen %s/%s failed: %v", fw.Name, fw.Proto, fw.Listen, err)
			continue
		}
		f.active[fw.Name] = l
		status[fw.Name] = ""
	}
	f.status = status
}

// Status returns a snapshot of each forward's runtime state by name.
func (f *Forwarder) Status() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.status))
	for k, v := range f.status {
		out[k] = v
	}
	return out
}

// Shutdown stops every listener.
func (f *Forwarder) Shutdown() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, l := range f.active {
		l.stop()
		delete(f.active, name)
	}
}

// fwdListener is one open listening socket and its accept/read loop (TCP or UDP).
type fwdListener struct {
	fwd  Forward
	ln   net.Listener   // tcp
	pc   net.PacketConn // udp
	quit chan struct{}
	wg   sync.WaitGroup
}

// startListener opens the TCP and/or UDP socket(s) for one forward, per Proto
// ("tcp", "udp", or "tcp+udp"; empty = tcp). Both share one quit/waitgroup.
func startListener(fw Forward) (*fwdListener, error) {
	l := &fwdListener{fwd: fw, quit: make(chan struct{})}
	if fw.Proto != "udp" { // tcp or tcp+udp (empty = tcp)
		if err := l.beginTCP(); err != nil {
			l.stop()
			return nil, err
		}
	}
	if fw.Proto == "udp" || fw.Proto == "tcp+udp" {
		if err := l.beginUDP(); err != nil {
			l.stop()
			return nil, err
		}
	}
	return l, nil
}

// ---------- TCP ----------

func (l *fwdListener) beginTCP() error {
	ln, err := net.Listen("tcp", l.fwd.Listen)
	if err != nil {
		return err
	}
	l.ln = ln
	l.wg.Add(1)
	go l.acceptLoop()
	log.Printf("forward %q listening on tcp %s -> %s", l.fwd.Name, l.fwd.Listen, l.fwd.Target)
	return nil
}

func (l *fwdListener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return // listener closed by stop() or broke
		}
		go l.handleTCP(conn)
	}
}

// handleTCP pipes one accepted connection to the target, both directions, with a
// proper half-close so each side sees EOF when the other finishes.
func (l *fwdListener) handleTCP(client net.Conn) {
	defer client.Close()
	target, err := net.DialTimeout("tcp", l.fwd.Target, 10*time.Second)
	if err != nil {
		log.Printf("forward %q dial %s failed: %v", l.fwd.Name, l.fwd.Target, err)
		return
	}
	defer target.Close()

	if l.fwd.ProxyProto {
		if h := proxyProtoV2Header(client.RemoteAddr(), client.LocalAddr()); h != nil {
			if _, err := target.Write(h); err != nil {
				return
			}
		}
	}

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if c, ok := dst.(*net.TCPConn); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(target, client)
	go pipe(client, target)
	<-done
	<-done
}

// ---------- UDP ----------

// udpSession maps one client source address to a dedicated socket toward the
// backend, with a reverse goroutine copying replies back to the client.
type udpSession struct {
	back *net.UDPConn
	last time.Time
}

func (l *fwdListener) beginUDP() error {
	target, err := net.ResolveUDPAddr("udp", l.fwd.Target)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", l.fwd.Listen)
	if err != nil {
		return err
	}
	l.pc = pc
	l.wg.Add(1)
	go l.udpLoop(target)
	log.Printf("forward %q listening on udp %s -> %s", l.fwd.Name, l.fwd.Listen, l.fwd.Target)
	return nil
}

func (l *fwdListener) udpLoop(target *net.UDPAddr) {
	defer l.wg.Done()
	sessions := map[string]*udpSession{}
	var mu sync.Mutex

	// idle session reaper
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-l.quit:
				return
			case <-t.C:
				mu.Lock()
				for k, s := range sessions {
					if time.Since(s.last) > udpSessionIdle {
						s.back.Close()
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, caddr, err := l.pc.ReadFrom(buf)
		if err != nil {
			// closed by stop(): tear down all sessions
			mu.Lock()
			for k, s := range sessions {
				s.back.Close()
				delete(sessions, k)
			}
			mu.Unlock()
			return
		}
		key := caddr.String()
		mu.Lock()
		s := sessions[key]
		if s == nil {
			back, derr := net.DialUDP("udp", nil, target)
			if derr != nil {
				mu.Unlock()
				log.Printf("forward %q dial udp %s failed: %v", l.fwd.Name, l.fwd.Target, derr)
				continue
			}
			s = &udpSession{back: back, last: time.Now()}
			sessions[key] = s
			// reverse: backend replies -> client
			l.wg.Add(1)
			go func(sess *udpSession, client net.Addr) {
				defer l.wg.Done()
				rbuf := make([]byte, 65535)
				for {
					rn, rerr := sess.back.Read(rbuf)
					if rerr != nil {
						return
					}
					l.pc.WriteTo(rbuf[:rn], client)
				}
			}(s, caddr)
		}
		s.last = time.Now()
		b := s.back
		mu.Unlock()
		b.Write(buf[:n])
	}
}

func (l *fwdListener) stop() {
	close(l.quit)
	if l.ln != nil {
		_ = l.ln.Close()
	}
	if l.pc != nil {
		_ = l.pc.Close()
	}
	l.wg.Wait()
}

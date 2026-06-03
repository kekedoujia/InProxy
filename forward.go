package main

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Forwarder runs the live TCP port forwards. It reconciles a set of desired
// Forward configs against the listeners actually open, starting/stopping as the
// admin edits them. Bind failures are recorded per-forward (surfaced in the UI)
// rather than aborting the whole apply.
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
	// stop listeners that are gone, disabled, or whose addr/target changed
	for name, l := range f.active {
		w, ok := want[name]
		if !ok || !w.Enabled || w.Listen != l.fwd.Listen || w.Target != l.fwd.Target {
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
			log.Printf("forward %q listen %s failed: %v", fw.Name, fw.Listen, err)
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

// Shutdown stops every listener (existing connections drain on their own).
func (f *Forwarder) Shutdown() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, l := range f.active {
		l.stop()
		delete(f.active, name)
	}
}

// fwdListener is one open listening socket and its accept loop.
type fwdListener struct {
	fwd  Forward
	ln   net.Listener
	quit chan struct{}
	wg   sync.WaitGroup
}

func startListener(fw Forward) (*fwdListener, error) {
	ln, err := net.Listen("tcp", fw.Listen)
	if err != nil {
		return nil, err
	}
	l := &fwdListener{fwd: fw, ln: ln, quit: make(chan struct{})}
	l.wg.Add(1)
	go l.acceptLoop()
	log.Printf("forward %q listening on %s -> %s", fw.Name, fw.Listen, fw.Target)
	return l, nil
}

func (l *fwdListener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.quit:
				return // listener closed by stop()
			default:
				return // listener broke; nothing more to accept
			}
		}
		go l.handle(conn)
	}
}

// handle pipes one accepted connection to the target, both directions, with a
// proper half-close so each side sees EOF when the other finishes.
func (l *fwdListener) handle(client net.Conn) {
	defer client.Close()
	target, err := net.DialTimeout("tcp", l.fwd.Target, 10*time.Second)
	if err != nil {
		log.Printf("forward %q dial %s failed: %v", l.fwd.Name, l.fwd.Target, err)
		return
	}
	defer target.Close()

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if c, ok := dst.(*net.TCPConn); ok {
			c.CloseWrite() // signal EOF to the peer instead of a hard reset
		}
		done <- struct{}{}
	}
	go pipe(target, client)
	go pipe(client, target)
	<-done
	<-done
}

func (l *fwdListener) stop() {
	close(l.quit)
	_ = l.ln.Close()
	l.wg.Wait()
}

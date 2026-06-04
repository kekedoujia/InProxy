package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		proxyAddr    = env("PROXY_ADDR", ":443")           // external HTTPS proxy (all interfaces)
		redirectAddr = env("HTTP_REDIRECT_ADDR", ":80")    // HTTP->HTTPS redirect / ACME challenge (empty disables)
		adminAddr    = env("ADMIN_ADDR", ":8443")          // admin UI listener (bound to internal IP at install time)
		adminTLS     = env("ADMIN_TLS", "false") == "true" // whether the admin UI also uses HTTPS
		internalCIDR = env("INTERNAL_CIDR", "10.8.0.0/24,127.0.0.1/32,::1/128")
		configPath   = env("CONFIG_PATH", "/etc/inproxy/config.json")
		tlsMode      = env("TLS_MODE", "auto")                // auto | self | file
		externalHost = env("EXTERNAL_HOST", "")               // external domain, e.g. tools.aperture-x.com
		acmeCache    = env("ACME_CACHE", "/etc/inproxy/acme") // Let's Encrypt cert cache dir
		acmeEmail    = env("ACME_EMAIL", "")                  // ACME account email (optional)
		certPath     = env("TLS_CERT", "/etc/inproxy/tls/cert.pem")
		keyPath      = env("TLS_KEY", "/etc/inproxy/tls/key.pem")
		password     = os.Getenv("ADMIN_PASSWORD")
	)
	if password == "" {
		log.Fatal("ADMIN_PASSWORD must be set to the admin UI password")
	}

	store, err := NewStore(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	auth, err := NewAuth(password, internalCIDR)
	if err != nil {
		log.Fatalf("failed to init auth: %v", err)
	}

	// TCP port forwarders: reconcile listeners whenever the config changes,
	// and bring up whatever is configured at startup.
	forwarder := NewForwarder()
	store.SetForwardListener(forwarder.Apply)
	forwarder.Apply(store.ListForwards())

	// Kernel DNAT rules (iptables): same reconcile-on-change + apply-on-start.
	dnat := NewDNATManager()
	store.SetDNATListener(dnat.Apply)
	dnat.Apply(store.ListDNAT())

	admin := NewAdmin(store, auth, forwarder, dnat)

	// the main HTTPS listener's public port (used to match domain forwards on it)
	_, httpsPort, _ := net.SplitHostPort(proxyAddr)
	mainPort := 443
	if p, e := strconv.Atoi(httpsPort); e == nil && p != 0 {
		mainPort = p
	}

	// External proxy handler: terminate-mode domains and path routes (the admin UI
	// is never exposed). Passthrough domains are diverted earlier at the TLS layer.
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_healthz" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}
		// a whole hostname mapped to one backend (terminate mode) wins over path routes
		if cp, ok := store.MatchDomain(hostOnly(r.Host), mainPort); ok && cp.ManageCert {
			cp.serve(w, r)
			return
		}
		if c, ok := store.Match(r.URL.Path); ok {
			c.serve(w, r)
			return
		}
		http.NotFound(w, r)
	})

	// Configure external HTTPS: pick the cert source by TLS_MODE.
	var (
		proxyTLSConf *tls.Config  // TLS config for the :443 listener (autocert or file-based)
		redirectH    http.Handler = redirectToHTTPS(httpsPort)
	)
	switch tlsMode {
	case "auto":
		if externalHost == "" {
			log.Fatal("TLS_MODE=auto requires EXTERNAL_HOST to be your domain (e.g. tools.aperture-x.com)")
		}
		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			// allow the main host plus any terminate-mode domain, so Let's Encrypt
			// issues certs for them on first request. Passthrough domains are
			// excluded — the backend owns their cert.
			HostPolicy: func(_ context.Context, host string) error {
				if strings.EqualFold(host, externalHost) || store.IsTerminateHost(host) {
					return nil
				}
				return fmt.Errorf("acme: host %q is not configured", host)
			},
			Cache: autocert.DirCache(acmeCache),
			Email: acmeEmail,
		}
		proxyTLSConf = m.TLSConfig()
		// :80 serves the ACME http-01 challenge and redirects everything else to HTTPS
		redirectH = m.HTTPHandler(redirectToHTTPS(httpsPort))
		log.Printf("TLS mode: Let's Encrypt automatic certificates (domain %s)", externalHost)
	case "self", "file":
		if tlsMode == "self" {
			if err := ensureTLS(certPath, keyPath, []string{"127.0.0.1", "::1", externalHost}); err != nil {
				log.Fatalf("failed to generate self-signed certificate: %v", err)
			}
		} else if !fileExists(certPath) || !fileExists(keyPath) {
			log.Fatalf("TLS_MODE=file requires both TLS_CERT(%s) and TLS_KEY(%s) to exist", certPath, keyPath)
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			log.Fatalf("failed to load certificate %s: %v", certPath, err)
		}
		proxyTLSConf = &tls.Config{Certificates: []tls.Certificate{cert}}
		log.Printf("TLS mode: %s certificate %s", tlsMode, certPath)
	default:
		log.Fatalf("unknown TLS_MODE=%q (choose auto|self|file)", tlsMode)
	}

	// Domain router: passthrough/terminate by SNI. The main :443 listener is wrapped
	// below; extra ports get their own listeners, reconciled on config change.
	redirectPort := 80
	if redirectAddr != "" {
		if _, rp, e := net.SplitHostPort(redirectAddr); e == nil {
			if n, e2 := strconv.Atoi(rp); e2 == nil && n != 0 {
				redirectPort = n
			}
		}
	}
	domainRouter := NewDomainRouter(store, proxyTLSConf, mainPort, redirectPort)
	store.SetDomainListener(domainRouter.Apply)
	domainRouter.Apply()

	var servers []*http.Server
	var wg sync.WaitGroup
	run := func(name string, s *http.Server, serve func() error) {
		servers = append(servers, s)
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("%s listening on %s", name, s.Addr)
			if err := serve(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("%s exited: %v", name, err)
			}
		}()
	}

	// 1) External HTTPS proxy. The raw :443 listener is wrapped so passthrough
	//    domains are spliced to their backend before TLS; everything else
	//    (terminate domains, tools path routes, ACME) is TLS-terminated here.
	rawProxyLn, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", proxyAddr, err)
	}
	proxySNI := newSNIListener(rawProxyLn, func(host string) sniDecision {
		if cp, ok := store.MatchDomain(host, mainPort); ok && !cp.ManageCert {
			return sniDecision{action: actPassthrough, target: cp.Target}
		}
		return sniDecision{action: actAccept} // terminate domains / tools / ACME fall through
	})
	proxySrv := &http.Server{Addr: proxyAddr, Handler: proxyHandler, ReadHeaderTimeout: 15 * time.Second}
	run("external HTTPS proxy", proxySrv, func() error {
		return proxySrv.Serve(tls.NewListener(proxySNI, proxyTLSConf))
	})

	// 2) Internal admin UI (dedicated port, bound to the internal IP at install time;
	//    protected by both the IP allowlist and a password).
	adminSrv := &http.Server{Addr: adminAddr, Handler: admin.Handler(), ReadHeaderTimeout: 15 * time.Second}
	run("internal admin UI ("+internalCIDR+")", adminSrv, func() error {
		if adminTLS {
			// reuse the self/file certificate; auto mode does not issue a cert for the admin host
			return adminSrv.ListenAndServeTLS(certPath, keyPath)
		}
		return adminSrv.ListenAndServe()
	})

	// 3) :80 — domain :80 forwards reverse-proxy to their backend (plaintext HTTP);
	//    everything else is the HTTP->HTTPS redirect + ACME challenges.
	if redirectAddr != "" {
		base80 := redirectH
		h80 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cp, ok := store.MatchDomain(hostOnly(r.Host), redirectPort); ok && cp.proxy != nil {
				cp.serve(w, r)
				return
			}
			base80.ServeHTTP(w, r)
		})
		redSrv := &http.Server{Addr: redirectAddr, Handler: h80, ReadHeaderTimeout: 15 * time.Second}
		run("HTTP->HTTPS redirect", redSrv, redSrv.ListenAndServe)
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	forwarder.Shutdown()
	dnat.Shutdown()
	domainRouter.Shutdown()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
	wg.Wait()
}

// hostOnly strips any :port from a request Host.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// redirectToHTTPS 301-redirects any HTTP request to HTTPS on the same host.
func redirectToHTTPS(httpsPort string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		target := "https://" + host
		if httpsPort != "" && httpsPort != "443" {
			target += ":" + httpsPort
		}
		target += r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}

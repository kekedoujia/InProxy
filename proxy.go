package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// buildProxy constructs a reverse proxy for one route.
func buildProxy(r Route) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(r.Target)
	if err != nil {
		return nil, err
	}
	prefix := "/" + r.Prefix

	// Tune the connection pool to the configured concurrency. The default
	// transport caps idle connections per host at 2, which causes connection
	// churn under load; size the pool to the concurrency limit instead.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if r.MaxConcurrent > 0 {
		tr.MaxConnsPerHost = r.MaxConcurrent
		tr.MaxIdleConnsPerHost = r.MaxConcurrent
	} else {
		tr.MaxIdleConnsPerHost = 100
	}

	rp := &httputil.ReverseProxy{
		Transport: tr,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host

			path := req.URL.Path
			if r.StripPrefix {
				path = strings.TrimPrefix(path, prefix)
				if path == "" {
					path = "/"
				}
			}
			req.URL.Path = singleJoiningSlash(target.Path, path)
			req.URL.RawPath = "" // let net/http re-encode from Path

			// backends that match by virtual host need the right Host
			req.Host = target.Host

			// forwarding headers so the backend knows the real external request
			if _, ok := req.Header["X-Forwarded-Host"]; !ok {
				req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
			}
			req.Header.Set("X-Forwarded-Prefix", prefix)
			// X-Forwarded-For is appended automatically by ReverseProxy; add Proto here
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, e error) {
			log.Printf("proxy error [%s -> %s]: %v", prefix, target, e)
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "502 Bad Gateway: backend %s is unreachable (%v)", target.Host, e)
		},
	}
	return rp, nil
}

// buildTerminateProxy constructs a reverse proxy for a terminate-mode (manage-cert)
// domain forward: inproxy has already terminated TLS, this proxies to the backend.
// The backend can be http or https (BackendTLS), and https verification can be
// skipped for self-signed internal services. The client's Host is preserved so
// the backend's own vhost logic and generated links stay correct.
func buildTerminateProxy(host string, f PortForward) (*httputil.ReverseProxy, error) {
	scheme := "http"
	if f.BackendTLS {
		scheme = "https"
	}
	target, err := url.Parse(scheme + "://" + f.Target)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 100
	if f.BackendTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: f.SkipVerify}
		if !f.SkipVerify {
			tr.TLSClientConfig.ServerName = target.Hostname()
		}
	}
	rp := &httputil.ReverseProxy{
		Transport: tr,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
			req.URL.RawPath = ""
			// keep req.Host as the public hostname (do not overwrite it)
			if _, ok := req.Header["X-Forwarded-Host"]; !ok {
				req.Header.Set("X-Forwarded-Host", req.Host)
			}
			req.Header.Set("X-Forwarded-Proto", "https")
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, e error) {
			log.Printf("domain proxy error [%s -> %s]: %v", host, target, e)
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "502 Bad Gateway: backend %s is unreachable (%v)", target.Host, e)
		},
	}
	return rp, nil
}

// serve proxies a terminate-mode request matched by hostname.
func (c *compiledPF) serve(w http.ResponseWriter, r *http.Request) {
	c.proxy.ServeHTTP(w, r)
}

// serve forwards the request, enforcing the route's concurrency limit if set.
// When the limit is reached, the request waits for a slot; if the client
// disconnects while waiting it gives up its place rather than piling up.
func (c *compiledRoute) serve(w http.ResponseWriter, r *http.Request) {
	if c.limiter != nil {
		select {
		case c.limiter <- struct{}{}:
			defer func() { <-c.limiter }()
		case <-r.Context().Done():
			http.Error(w, "503 Service Unavailable: request cancelled while waiting for a free slot", http.StatusServiceUnavailable)
			return
		}
	}
	c.proxy.ServeHTTP(w, r)
}

// singleJoiningSlash joins two path segments with exactly one slash.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		if a == "" {
			return b
		}
		return a + "/" + b
	}
	return a + b
}

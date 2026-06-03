package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const sessionCookie = "inproxy_session"
const sessionTTL = 12 * time.Hour

// Auth handles admin access control: source IP allowlist + password login.
type Auth struct {
	password string
	nets     []*net.IPNet
	secret   []byte // session signing key, derived from the password
}

// NewAuth builds the authenticator. cidrs is a comma-separated allowlist of
// networks permitted to reach the admin UI.
func NewAuth(password string, cidrs string) (*Auth, error) {
	a := &Auth{password: password}
	sum := sha256.Sum256([]byte("inproxy-session-key:" + password))
	a.secret = sum[:]
	for _, c := range strings.Split(cidrs, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		a.nets = append(a.nets, n)
	}
	return a, nil
}

// IPAllowed reports whether the request's source IP is in an allowed network.
func (a *Auth) IPAllowed(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckPassword compares the password in constant time.
func (a *Auth) CheckPassword(p string) bool {
	return subtle.ConstantTimeCompare([]byte(p), []byte(a.password)) == 1
}

// IssueCookie issues a signed session cookie with an expiry.
func (a *Auth) IssueCookie(w http.ResponseWriter, secure bool) {
	exp := time.Now().Add(sessionTTL).Unix()
	payload := strconv.FormatInt(exp, 10)
	value := payload + "." + a.sign(payload)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/_admin",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(exp, 0),
	})
}

// ClearCookie logs out the session.
func (a *Auth) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/_admin",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// SessionValid checks that the request's session cookie is valid and unexpired.
func (a *Auth) SessionValid(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payload, mac := parts[0], parts[1]
	if subtle.ConstantTimeCompare([]byte(mac), []byte(a.sign(payload))) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(payload, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return true
}

func (a *Auth) sign(payload string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

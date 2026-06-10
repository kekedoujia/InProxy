package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

//go:embed templates/*.html
var templatesFS embed.FS

var tmpl = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

// Admin provides the HTTP handlers for the management UI.
type Admin struct {
	store *Store
	auth  *Auth
	fwd   *Forwarder
	dnat  *DNATManager
}

func NewAdmin(store *Store, auth *Auth, fwd *Forwarder, dnat *DNATManager) *Admin {
	return &Admin{store: store, auth: auth, fwd: fwd, dnat: dnat}
}

// Handler returns the handler serving the admin UI under /_admin.
func (ad *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/_admin/login", ad.login)
	mux.HandleFunc("/_admin/logout", ad.logout)
	mux.HandleFunc("/_admin/save", ad.requireAuth(ad.save))
	mux.HandleFunc("/_admin/delete", ad.requireAuth(ad.delete))
	mux.HandleFunc("/_admin/forwards", ad.requireAuth(ad.forwards))
	mux.HandleFunc("/_admin/forwards/save", ad.requireAuth(ad.saveForward))
	mux.HandleFunc("/_admin/forwards/delete", ad.requireAuth(ad.deleteForward))
	mux.HandleFunc("/_admin/dnat", ad.requireAuth(ad.dnatPage))
	mux.HandleFunc("/_admin/dnat/save", ad.requireAuth(ad.saveDNAT))
	mux.HandleFunc("/_admin/dnat/delete", ad.requireAuth(ad.deleteDNAT))
	mux.HandleFunc("/_admin/domains", ad.requireAuth(ad.domains))
	mux.HandleFunc("/_admin/domains/save", ad.requireAuth(ad.saveDomain))
	mux.HandleFunc("/_admin/domains/delete", ad.requireAuth(ad.deleteDomain))
	mux.HandleFunc("/_admin", ad.requireAuth(ad.dashboard))
	mux.HandleFunc("/_admin/", ad.requireAuth(ad.dashboard))
	// on a dedicated port, hitting the root goes straight to the admin UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/_admin", http.StatusSeeOther)
	})
	// the IP allowlist is the first gate: every request passes through it
	return ad.ipGate(mux)
}

// ipGate blocks access from networks not in the allowlist.
func (ad *Admin) ipGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ad.auth.IPAllowed(r) {
			http.Error(w, "403 Forbidden: the admin UI is restricted to the internal network", http.StatusForbidden)
			log.Printf("admin denied (ip not allowed): %s %s", r.RemoteAddr, r.URL.Path)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth wraps a handler that requires an authenticated session.
func (ad *Admin) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ad.auth.SessionValid(r) {
			http.Redirect(w, r, "/_admin/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

func (ad *Admin) login(w http.ResponseWriter, r *http.Request) {
	if ad.auth.SessionValid(r) {
		http.Redirect(w, r, "/_admin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if ad.auth.CheckPassword(r.FormValue("password")) {
			ad.auth.IssueCookie(w, r.TLS != nil)
			http.Redirect(w, r, "/_admin", http.StatusSeeOther)
			return
		}
		ad.render(w, "login.html", map[string]any{"Error": "Incorrect password"})
		return
	}
	ad.render(w, "login.html", nil)
}

func (ad *Admin) logout(w http.ResponseWriter, r *http.Request) {
	ad.auth.ClearCookie(w)
	http.Redirect(w, r, "/_admin/login", http.StatusSeeOther)
}

func (ad *Admin) dashboard(w http.ResponseWriter, r *http.Request) {
	sites := ad.store.ListSites()
	js, _ := json.Marshal(sites)
	ad.render(w, "dashboard.html", map[string]any{
		"Active":    "http",
		"Sites":     sites,
		"SitesJSON": template.JS(js),
		"Notice":    r.URL.Query().Get("notice"),
		"Error":     r.URL.Query().Get("error"),
	})
}

func (ad *Admin) save(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin", http.StatusSeeOther)
		return
	}
	var routes []Route
	if s := strings.TrimSpace(r.FormValue("routes_json")); s != "" {
		if err := json.Unmarshal([]byte(s), &routes); err != nil {
			ad.redirectMsg(w, r, "error", "could not read routes: "+err.Error())
			return
		}
	}
	site := HTTPSite{
		Host:        strings.TrimSpace(r.FormValue("host")),
		Description: strings.TrimSpace(r.FormValue("description")),
		Routes:      routes,
	}
	oldHost := strings.TrimSpace(r.FormValue("old_host"))
	if err := ad.store.UpsertSite(oldHost, site); err != nil {
		ad.redirectMsg(w, r, "error", err.Error())
		return
	}
	ad.redirectMsg(w, r, "notice", "Saved "+site.Host+" (certificate is obtained on first HTTPS request)")
}

func (ad *Admin) delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin", http.StatusSeeOther)
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	if err := ad.store.DeleteSite(host); err != nil {
		ad.redirectMsg(w, r, "error", err.Error())
		return
	}
	ad.redirectMsg(w, r, "notice", "Deleted "+host)
}

func (ad *Admin) domains(w http.ResponseWriter, r *http.Request) {
	domains := ad.store.ListDomains()
	js, _ := json.Marshal(domains)
	ad.render(w, "domains.html", map[string]any{
		"Active":      "domains",
		"Domains":     domains,
		"DomainsJSON": template.JS(js),
		"Notice":      r.URL.Query().Get("notice"),
		"Error":       r.URL.Query().Get("error"),
	})
}

func (ad *Admin) saveDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin/domains", http.StatusSeeOther)
		return
	}
	var forwards []PortForward
	if s := strings.TrimSpace(r.FormValue("forwards_json")); s != "" {
		if err := json.Unmarshal([]byte(s), &forwards); err != nil {
			ad.redirectMsgTo(w, r, "/_admin/domains", "error", "could not read port forwards: "+err.Error())
			return
		}
	}
	d := Domain{
		Host:        strings.TrimSpace(r.FormValue("host")),
		Description: strings.TrimSpace(r.FormValue("description")),
		Forwards:    forwards,
	}
	oldHost := strings.TrimSpace(r.FormValue("old_host"))
	if err := ad.store.UpsertDomain(oldHost, d); err != nil {
		ad.redirectMsgTo(w, r, "/_admin/domains", "error", err.Error())
		return
	}
	ad.redirectMsgTo(w, r, "/_admin/domains", "notice", "Saved domain "+d.Host+" (terminate-mode certs are obtained on first HTTPS request)")
}

func (ad *Admin) deleteDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin/domains", http.StatusSeeOther)
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	if err := ad.store.DeleteDomain(host); err != nil {
		ad.redirectMsgTo(w, r, "/_admin/domains", "error", err.Error())
		return
	}
	ad.redirectMsgTo(w, r, "/_admin/domains", "notice", "Deleted domain "+host)
}

// dnatView is a DNAT rule plus its live iptables status for the table.
type dnatView struct {
	DNATRule
	Status string // "active" | "disabled" | "error: ..."
}

func (ad *Admin) dnatPage(w http.ResponseWriter, r *http.Request) {
	st, gerr := ad.dnat.Status()
	var rows []dnatView
	for _, d := range ad.store.ListDNAT() {
		s := st[d.Name]
		switch {
		case !d.Enabled:
			s = "disabled"
		case s == "":
			s = "active"
		}
		rows = append(rows, dnatView{DNATRule: d, Status: s})
	}
	errMsg := r.URL.Query().Get("error")
	if errMsg == "" && gerr != "" {
		errMsg = "iptables error: " + gerr
	}
	ad.render(w, "dnat.html", map[string]any{
		"Active": "dnat",
		"Rules":  rows,
		"Notice": r.URL.Query().Get("notice"),
		"Error":  errMsg,
	})
}

func (ad *Admin) saveDNAT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin/dnat", http.StatusSeeOther)
		return
	}
	port := 0
	if v := strings.TrimSpace(r.FormValue("listen_port")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			ad.redirectMsgTo(w, r, "/_admin/dnat", "error", "public port must be a number")
			return
		}
		port = n
	}
	d := DNATRule{
		Name:        strings.TrimSpace(r.FormValue("name")),
		Proto:       strings.TrimSpace(r.FormValue("proto")),
		ListenPort:  port,
		Target:      strings.TrimSpace(r.FormValue("target")),
		SNAT:        r.FormValue("snat") == "on",
		Description: strings.TrimSpace(r.FormValue("description")),
		Enabled:     r.FormValue("enabled") == "on",
	}
	oldName := strings.TrimSpace(r.FormValue("old_name"))
	if err := ad.store.UpsertDNAT(oldName, d); err != nil {
		ad.redirectMsgTo(w, r, "/_admin/dnat", "error", err.Error())
		return
	}
	if st, _ := ad.dnat.Status(); strings.HasPrefix(st[d.Name], "error:") {
		ad.redirectMsgTo(w, r, "/_admin/dnat", "error", "Saved, but applying to iptables failed — "+st[d.Name])
		return
	}
	ad.redirectMsgTo(w, r, "/_admin/dnat", "notice", "Saved DNAT rule "+d.Name)
}

func (ad *Admin) deleteDNAT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin/dnat", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if err := ad.store.DeleteDNAT(name); err != nil {
		ad.redirectMsgTo(w, r, "/_admin/dnat", "error", err.Error())
		return
	}
	ad.redirectMsgTo(w, r, "/_admin/dnat", "notice", "Deleted DNAT rule "+name)
}

// forwardView is a Forward plus its live runtime status for the table.
type forwardView struct {
	Forward
	Status string // "running" | "disabled" | "error: ..."
}

func (ad *Admin) forwards(w http.ResponseWriter, r *http.Request) {
	st := ad.fwd.Status()
	var rows []forwardView
	for _, f := range ad.store.ListForwards() {
		s := st[f.Name]
		switch {
		case !f.Enabled:
			s = "disabled"
		case s == "":
			s = "running"
		}
		rows = append(rows, forwardView{Forward: f, Status: s})
	}
	ad.render(w, "forwards.html", map[string]any{
		"Active":   "forward",
		"Forwards": rows,
		"Notice":   r.URL.Query().Get("notice"),
		"Error":    r.URL.Query().Get("error"),
	})
}

func (ad *Admin) saveForward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin/forwards", http.StatusSeeOther)
		return
	}
	f := Forward{
		Name:        strings.TrimSpace(r.FormValue("name")),
		Proto:       strings.TrimSpace(r.FormValue("proto")),
		Listen:      strings.TrimSpace(r.FormValue("listen")),
		Target:      strings.TrimSpace(r.FormValue("target")),
		ProxyProto:  r.FormValue("proxy_proto") == "on",
		Description: strings.TrimSpace(r.FormValue("description")),
		Enabled:     r.FormValue("enabled") == "on",
	}
	oldName := strings.TrimSpace(r.FormValue("old_name"))
	if err := ad.store.UpsertForward(oldName, f); err != nil {
		ad.redirectMsgTo(w, r, "/_admin/forwards", "error", err.Error())
		return
	}
	// surface a bind failure immediately rather than only as a table status
	if s := ad.fwd.Status()[f.Name]; strings.HasPrefix(s, "error:") {
		ad.redirectMsgTo(w, r, "/_admin/forwards", "error", "Saved, but listener failed — "+s)
		return
	}
	ad.redirectMsgTo(w, r, "/_admin/forwards", "notice", "Saved forward "+f.Name)
}

func (ad *Admin) deleteForward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin/forwards", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if err := ad.store.DeleteForward(name); err != nil {
		ad.redirectMsgTo(w, r, "/_admin/forwards", "error", err.Error())
		return
	}
	ad.redirectMsgTo(w, r, "/_admin/forwards", "notice", "Deleted forward "+name)
}

func (ad *Admin) redirectMsg(w http.ResponseWriter, r *http.Request, kind, msg string) {
	ad.redirectMsgTo(w, r, "/_admin", kind, msg)
}

func (ad *Admin) redirectMsgTo(w http.ResponseWriter, r *http.Request, base, kind, msg string) {
	u := base + "?" + kind + "=" + url.QueryEscape(msg)
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (ad *Admin) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template error %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

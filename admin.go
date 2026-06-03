package main

import (
	"embed"
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
}

func NewAdmin(store *Store, auth *Auth, fwd *Forwarder) *Admin {
	return &Admin{store: store, auth: auth, fwd: fwd}
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
	ad.render(w, "dashboard.html", map[string]any{
		"Active": "http",
		"Routes": ad.store.List(),
		"Notice": r.URL.Query().Get("notice"),
		"Error":  r.URL.Query().Get("error"),
	})
}

func (ad *Admin) save(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin", http.StatusSeeOther)
		return
	}
	maxConc := 0
	if v := strings.TrimSpace(r.FormValue("max_concurrent")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			ad.redirectMsg(w, r, "error", "max concurrency must be a non-negative integer (0 = unlimited)")
			return
		}
		maxConc = n
	}
	route := Route{
		Prefix:        strings.Trim(strings.TrimSpace(r.FormValue("prefix")), "/"),
		Target:        strings.TrimSpace(r.FormValue("target")),
		StripPrefix:   r.FormValue("strip_prefix") == "on",
		Description:   strings.TrimSpace(r.FormValue("description")),
		Enabled:       r.FormValue("enabled") == "on",
		MaxConcurrent: maxConc,
	}
	oldPrefix := strings.TrimSpace(r.FormValue("old_prefix"))
	if err := ad.store.Upsert(oldPrefix, route); err != nil {
		ad.redirectMsg(w, r, "error", err.Error())
		return
	}
	ad.redirectMsg(w, r, "notice", "Saved route /"+route.Prefix)
}

func (ad *Admin) delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/_admin", http.StatusSeeOther)
		return
	}
	prefix := strings.TrimSpace(r.FormValue("prefix"))
	if err := ad.store.Delete(prefix); err != nil {
		ad.redirectMsg(w, r, "error", err.Error())
		return
	}
	ad.redirectMsg(w, r, "notice", "Deleted route /"+prefix)
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
		Listen:      strings.TrimSpace(r.FormValue("listen")),
		Target:      strings.TrimSpace(r.FormValue("target")),
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

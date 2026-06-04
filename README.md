# inproxy

Expose internal HTTP services — scattered across different servers and ports on the
internal network (`10.8.0.x`) — under a single public host via **path prefixes**, always
over **HTTPS**. Internal users can reach them too. Ships with a management UI that is
**bound to the internal NIC, on a dedicated port, reachable only from the internal
network**, and runs as a **systemd** service.

```
                         ┌─────────────────────── inproxy (one host, dual NIC / VPN) ──────────────┐
external user ─HTTPS:443─►  external listener :443 (HTTPS) ─►  http://10.8.0.5:8080   (/finance)    │
tools.aperture-x.com     │  :80 ──301──► :443             ─►  http://10.8.0.7:3000   (/wiki)        │
internal user ──────────►│                                                                          │
                         │  admin listener 10.8.0.1:8443  (only 10.8.0.0/24 + password)             │
                         └──────────────────────────────────────────────────────────────────────────┘
```

- **Single binary**, Go standard library + `x/crypto/autocert`; just drop it on the host.
- **Two independent listeners**:
  - External `:443` — HTTPS reverse proxy, forwards business routes only, **never exposes the admin UI**.
  - Internal `<internal-IP>:<port>` — admin UI, bound to the internal NIC + IP allowlist + password.
- **HTTPS everywhere on the outside**, with three certificate modes:
  - `auto`: Let's Encrypt automatic issuance (recommended when you have a domain; browser-trusted).
  - `self`: auto-generated self-signed cert (works for a bare IP; browser warning).
  - `file`: bring your own certificate.
- **Path-prefix routing**, longest prefix wins; each route can independently **strip its prefix**.
- **Raw TCP port forwarding** (separate "Port forwarding" admin page): map a public listen
  port on this host to a `host:port` on an internal machine. Works for any TCP protocol
  (SSH, RDP, databases, …); listeners start/stop the moment you save.
- **Kernel DNAT** ("DNAT" admin page): destination-NAT a public port to an internal
  `host:port` via iptables — faster than userspace forwarding and supports **UDP**. Rules
  live in dedicated nat chains (`INPROXY_DNAT` / `INPROXY_POST`) so nothing else is touched;
  an optional per-rule SNAT (masquerade) fixes the return path for VPN/internal targets.
  Requires `CAP_NET_ADMIN` (granted by the systemd unit; the process stays non-root).
- **Domain routing by SNI** ("Domains" admin page): each domain maps public ports to an
  internal `ip:port`. Per port choose **terminate** (inproxy ends TLS with an automatic
  Let's Encrypt cert and reverse-proxies) or **passthrough** (the encrypted stream is
  forwarded as-is, so the backend serves its own cert — handy for a unified backend cert).
  Port `:80` is a plaintext HTTP reverse proxy (lets the backend run its own ACME/redirect).
  A connection that matches no domain falls through to normal handling (HTTP service / tools).
- Admin edits take effect **immediately**, no restart.
- WebSocket and streaming responses supported; injects `X-Forwarded-For/Host/Proto/Prefix`.

## Configuration (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | (required) | Admin UI password; refuses to start if unset |
| `PROXY_ADDR` | `:443` | External HTTPS proxy listener (all interfaces; internal users may use it too) |
| `HTTP_REDIRECT_ADDR` | `:80` | HTTP→HTTPS redirect; also ACME challenge in `auto` mode; empty disables |
| `TLS_MODE` | `auto` | `auto` (Let's Encrypt) / `self` (self-signed) / `file` (your own) |
| `EXTERNAL_HOST` | — | External domain, e.g. `tools.aperture-x.com`; required for `auto` |
| `ACME_EMAIL` | — | Let's Encrypt account email (optional) |
| `ACME_CACHE` | `/etc/inproxy/acme` | ACME certificate cache directory |
| `TLS_CERT`/`TLS_KEY` | `/etc/inproxy/tls/*.pem` | Cert paths for `self`/`file` modes |
| `ADMIN_ADDR` | `:8443` | Admin UI listener; set to `<internal-IP>:<port>` at install |
| `ADMIN_TLS` | `false` | Whether the admin UI also uses HTTPS (reuses self/file cert) |
| `INTERNAL_CIDR` | `10.8.0.0/24,127.0.0.1/32,::1/128` | Networks allowed to reach the admin UI; **the proxy is not restricted** |
| `CONFIG_PATH` | `/etc/inproxy/config.json` | Route config file |

## Build & local dev

```bash
make build      # produces the static binary ./inproxy
make run        # self-signed dev: proxy https://127.0.0.1:8443 , admin http://127.0.0.1:9443/_admin (password: dev)
```

## Deploy (systemd)

> The host needs both external (public IP / domain `tools.aperture-x.com`) and internal
> `10.8.0.x` connectivity (dual NIC or VPN).

```bash
make build                      # build (copy ./inproxy over if the target has no Go)
sudo ./deploy/install.sh ./inproxy
```

The installer asks interactively:

1. **Which NIC is internal / which is external** (it lists the NICs; pick by number).
2. **External domain** (enter `tools.aperture-x.com` → enables Let's Encrypt; leave empty → self-signed for the external IP).
3. **Admin UI port** (default `8443`, bound to the chosen internal IP).
4. **Admin password**.

Then:

```bash
sudo systemctl start inproxy
journalctl -u inproxy -f
```

- Public service: `https://tools.aperture-x.com/<prefix>/...`
- Admin UI: `http://<internal-IP>:<port>/_admin` (internal network only)

> **Let's Encrypt prerequisites**: the A record for `tools.aperture-x.com` points to the
> external IP, and ports `80`/`443` are reachable from the internet. The first start issues
> the certificate automatically (watch `journalctl`).

Binding `80`/`443` is granted via systemd's `CAP_NET_BIND_SERVICE`; the process still runs
as the non-root `inproxy` user.

## Usage

Open `http://<internal-IP>:<port>/_admin` from the internal network, sign in, and "Add route":

- **Public path prefix**: e.g. `finance` → public `https://tools.aperture-x.com/finance/...`
- **Backend address**: internal service `http://10.8.0.5:8080`
- **Strip prefix**: checked → `/finance/api` forwards as backend `/api`; unchecked → forwarded
  as-is, with an `X-Forwarded-Prefix: /finance` header so the backend can build correct links.

Changes take effect immediately.

## Security notes

- The admin UI is bound to the internal NIC on a dedicated port, so the outside cannot
  connect at all; it additionally enforces an IP allowlist + password (constant-time
  comparison, HMAC-SHA256 signed session valid 12h).
- The proxy is public and only forwards — **the proxied internal services must enforce
  their own authentication**.
- HTTPS is enforced externally; in `auto` mode certificates renew automatically.

## Layout

| File | Description |
|------|-------------|
| `main.go`    | entry: env vars, three listeners (HTTPS proxy / internal admin / :80 redirect), graceful shutdown |
| `tls.go`     | self-signed certificate generation (`self` mode) |
| `config.go`  | route + forward models, thread-safe store, JSON persistence (auto-migrates the legacy array form), validation |
| `proxy.go`   | reverse proxy construction, prefix stripping, forwarding headers |
| `forward.go` | runtime TCP port forwarders: reconcile listeners on config change, pipe connections |
| `dnat.go`    | runtime kernel DNAT: reconcile iptables nat chains on config change (needs CAP_NET_ADMIN) |
| `domains.go` | SNI peek/route: TLS passthrough splicing + per-port listeners for domain routing |
| `auth.go`    | IP allowlist + password login + signed session cookie |
| `admin.go` + `templates/` | admin UI handlers and pages (embedded in the binary) |
| `deploy/`    | systemd unit, env example, interactive installer |

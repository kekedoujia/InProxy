BINARY := inproxy
GO     := go

.PHONY: build run clean install

# Build a static single binary (no Go needed on the target host)
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o $(BINARY) .

# Local dev run (self-signed cert, high ports; admin UI reachable only from localhost)
# proxy https://127.0.0.1:8443  redirect http://127.0.0.1:8080  admin http://127.0.0.1:9443/_admin
run:
	ADMIN_PASSWORD=dev TLS_MODE=self EXTERNAL_HOST=127.0.0.1 \
	PROXY_ADDR=:8443 HTTP_REDIRECT_ADDR=:8080 ADMIN_ADDR=127.0.0.1:9443 \
	INTERNAL_CIDR=127.0.0.1/32,::1/128 \
	TLS_CERT=./dev-cert.pem TLS_KEY=./dev-key.pem \
	CONFIG_PATH=./config.dev.json \
	$(GO) run .

# Install as a systemd service (needs root)
install: build
	sudo ./deploy/install.sh ./$(BINARY)

clean:
	rm -f $(BINARY)

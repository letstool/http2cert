# CLAUDE.md — http2cert

This file provides context for AI-assisted development on the `http2cert` project.

---

## Project overview

`http2cert` is a single-binary HTTP gateway that exposes X.509 certificate inspection as a JSON REST API.
It is written entirely in Go and embeds all static assets (web UI, favicon, OpenAPI spec) at compile time using `//go:embed` directives, so the resulting binary has zero runtime file dependencies.

The server accepts `POST /api/v1/certinfo` requests and returns fully parsed certificate chains as structured JSON — equivalent to `openssl x509 -noout -text`. Two input modes are supported: dialing a live TLS endpoint to retrieve its certificate chain, or parsing raw certificate bytes (PEM or DER) supplied directly in the request body.

---

## Repository layout

```
.
+-- api/
|   +-- swagger.yaml                  # OpenAPI 3.1 source (human-editable)
+-- build/
|   +-- Dockerfile                    # Two-stage Docker build (builder + scratch runtime)
+-- cmd/
|   +-- certinfo/
|   |   +-- main.go                   # Standalone CLI: parse a PEM/DER file and print JSON
|   +-- http2cert/
|       +-- main.go                   # HTTP server entry point
|       +-- static/
|           +-- favicon.png           # Embedded at build time
|           +-- index.html            # Embedded web UI (dark/light themes, 15 languages)
|           +-- openapi.json          # Embedded OpenAPI spec (generated from swagger.yaml)
+-- internal/
|   +-- api/
|       +-- handler.go                # HTTP handler: request parsing, routing, response writing
|       +-- handler_test.go           # Unit tests for the handler (mock fetcher, no network)
|       +-- types.go                  # Request/Response/SourceInfo types and result codes
+-- pkg/
|   +-- certfetch/
|   |   +-- fetch.go                  # TLS dialer: connects, handshakes, returns raw chain
|   +-- certinfo/
|       +-- certinfo.go               # X.509 parser: builds CertificateInfo from x509.Certificate
|       +-- certinfo_test.go          # Unit tests for the parser
|       +-- chain.go                  # ParseChain: iterates over all PEM blocks in a bundle
|       +-- types.go                  # All JSON output types (CertificateInfo and sub-structs)
+-- scripts/
|   +-- 000_init.sh                   # go mod tidy
|   +-- 999_test.sh                   # Integration smoke test (curl + jq)
|   +-- linux_build.sh                # Native static binary build
|   +-- linux_run.sh                  # Run binary on Linux
|   +-- docker_build.sh               # Build Docker image
|   +-- docker_run.sh                 # Run Docker container
|   +-- windows_build.cmd             # Native build on Windows
|   +-- windows_run.cmd               # Run binary on Windows
+-- go.mod
+-- go.sum
+-- LICENSE                           # MIT
+-- README.md
+-- CLAUDE.md                         # This file
```

---

## Key design decisions

- **Layered package structure**: the codebase is split into three layers. `pkg/certfetch` handles TLS dialing only. `pkg/certinfo` handles X.509 parsing only, with no HTTP knowledge. `internal/api` wires them together behind the HTTP handler. `cmd/http2cert` is the thin entry point that registers routes and starts the server.
- **Embedded assets**: `favicon.png`, `index.html`, and `openapi.json` are embedded with `//go:embed`. Any change to these files is picked up at the next `go build` — no copy step needed.
- **Static binary**: the build uses `-tags netgo` and `-ldflags "-extldflags -static"` to produce a fully self-contained binary with no libc dependency. Do not introduce `cgo` dependencies.
- **No framework**: the HTTP layer uses only the standard library (`net/http`). Do not add a router or web framework.
- **No stdlib dependencies beyond standard library**: all X.509 parsing uses `crypto/x509`, `crypto/tls`, `encoding/asn1`, and related packages from the Go standard library. No third-party certificate parsing library is used.
- **InsecureSkipVerify is intentional**: `certfetch` sets `InsecureSkipVerify: true` so that expired, self-signed, and otherwise invalid certificates can still be inspected. The goal is observation, not authentication.
- **Unknown extensions are preserved**: any X.509 v3 extension whose OID is not explicitly handled is captured in the `unknown_extensions` array as a hex-encoded value, so no information is silently discarded.
- **Standalone CLI**: `cmd/certinfo` provides a command-line tool that reuses `pkg/certinfo` directly to parse a PEM/DER file and print JSON to stdout, without starting an HTTP server.

---

## Environment variables & CLI flags

Every configuration value can be set via an environment variable **or** a command-line flag. The flag always takes priority. Resolution order: **CLI flag -> environment variable -> hard-coded default**.

| Environment variable | CLI flag    | Default           | Description                                                                      |
|----------------------|-------------|-------------------|----------------------------------------------------------------------------------|
| `LISTEN_ADDR`        | `-addr`     | `127.0.0.1:8080`  | Listen address. A bare port is not accepted; use `host:port` format.             |
| `DIAL_TIMEOUT`       | `-timeout`  | `10s`             | Server-wide TLS dial+handshake timeout. Go duration format: `5s`, `1m`, `1m30s`.|
| `LOG_JSON`           | `-json`     | `false`           | Emit structured JSON logs instead of plain text. Accepts `true`/`false`/`1`/`0`.|

CLI flags are parsed with the standard library `flag` package. Any new configuration entry must expose both a flag and its environment variable counterpart. Invalid values in environment variables cause the server to exit immediately with a descriptive error message on stderr.

---

## Build & run commands

```bash
# Initialise / tidy dependencies
bash scripts/000_init.sh

# Build native static binary -> ./out/http2cert
bash scripts/linux_build.sh

# Run (sets LISTEN_ADDR=0.0.0.0:8080)
bash scripts/linux_run.sh

# Build Docker image -> letstool/http2cert:latest
bash scripts/docker_build.sh

# Run Docker container
bash scripts/docker_run.sh

# Smoke test (server must be running on :8080)
bash scripts/999_test.sh

# Unit tests
go test ./...
```

---

## API contract

### Endpoint

```
POST /api/v1/certinfo
Content-Type: application/json
```

### Request fields

Exactly one of `socket` or `raw_cert_data` must be provided. They are mutually exclusive.

| Field           | Type      | Required | Notes                                                                                 |
|-----------------|-----------|----------|---------------------------------------------------------------------------------------|
| `socket`        | `string`  | (A)      | `host:port` to dial. Accepts domain names, IPv4, and `[IPv6]:port`.                  |
| `sni`           | `string`  | No       | SNI override for the TLS ClientHello. Defaults to the host part of `socket`.          |
| `timeout`       | `int`     | No       | Per-request timeout in seconds. Range: `1-120`. Socket mode only.                     |
| `raw_cert_data` | `string`  | (B)      | PEM or DER bytes. Format is auto-detected. Supports single certs and PEM chains.      |

### Response result codes

| Value             | HTTP status | Meaning                                                                |
|-------------------|-------------|------------------------------------------------------------------------|
| `SUCCESS`         | 200         | At least one certificate was parsed and returned in `answers`          |
| `INVALID_INPUT`   | 400         | Malformed request: bad JSON, both/neither fields, bad timeout value    |
| `NOTFOUND`        | 502         | Host unreachable: DNS failure, connection refused, network timeout     |
| `TLS_ERROR`       | 502         | TCP connection succeeded but TLS handshake failed                      |
| `NO_CERTIFICATES` | 200         | Connection or parse succeeded but zero certificates were returned      |
| `ERROR`           | 500/502     | Internal or unexpected server error                                    |

Error responses always carry a `message` field with a human-readable explanation. The `answers` field is always present (empty array on error, never null).

### Other endpoints

| Method | Path            | Description                        |
|--------|-----------------|------------------------------------|
| `GET`  | `/`             | Embedded interactive web UI        |
| `GET`  | `/openapi.json` | OpenAPI 3.1 specification          |
| `GET`  | `/favicon.png`  | Application icon                   |

---

## Web UI

The UI is a self-contained single-file HTML/JS/CSS application embedded in the binary.

- **Themes**: dark and light, switchable via a toggle button.
- **Languages**: 15 locales built in — Arabic (`ar`), Bengali (`bn`), Chinese (`zh`), German (`de`), English (`en`), Spanish (`es`), French (`fr`), Hindi (`hi`), Indonesian (`id`), Japanese (`ja`), Korean (`ko`), Portuguese (`pt`), Russian (`ru`), Urdu (`ur`), Vietnamese (`vi`). Language is selected from a dropdown.
- **RTL support**: Arabic and Urdu automatically switch the layout to right-to-left.
- The UI calls `POST /api/v1/certinfo` and renders results in a table.
- The OpenAPI spec is also served at `/openapi.json` for use with tools such as Swagger UI or Postman.

To modify the UI, edit `cmd/http2dns/static/index.html` and rebuild.
To update the API spec, edit `api/swagger.yaml`, regenerate `openapi.json`, and rebuild.

--- 

## Adding support for a new X.509 extension

1. Add the OID constant to the `var (...)` block near the top of `pkg/certinfo/certinfo.go`.
2. Add the corresponding struct fields to `Extensions` in `pkg/certinfo/types.go`, with appropriate `json` tags.
3. Add a `case` branch inside `parseExtensions()` in `pkg/certinfo/certinfo.go` to decode the raw ASN.1 extension value and populate the new struct fields. Mark the OID as handled (`handled[oidStr] = true`).
4. Update `api/swagger.yaml` to document the new fields in the `Extensions` schema.
5. Regenerate `cmd/http2cert/static/openapi.json` from the updated spec.
6. Rebuild.

---

## Constraints & conventions

- Go version: **1.22+**
- No `cgo`. Keep `CGO_ENABLED=0`.
- No additional HTTP frameworks or routers.
- No third-party certificate or cryptography libraries. Use only the Go standard library (`crypto/x509`, `crypto/tls`, `encoding/asn1`, etc.).
- Error responses always return a JSON body with `result` and `message` fields — never a plain-text error.
- The `answers` field is always present in the response body, even on error (empty array, never `null`).
- `timeout` is validated on receipt: values outside `[1, 120]` are rejected with `INVALID_INPUT`. Using `timeout` alongside `raw_cert_data` is also rejected.
- `InsecureSkipVerify` is always `true` in `certfetch`. Do not change this: the purpose of the tool is inspection, and rejecting invalid certificates would defeat it.
- The server never logs request bodies; avoid adding logging that could expose certificate contents or queried hostnames.
- All code, identifiers, comments, and documentation must be written in **English**. No icons, emoji, or non-ASCII decorations in comments or doc strings.
- **Every configuration environment variable must have a corresponding command-line flag** (parsed via the standard library `flag` package). The flag always takes priority over the environment variable. The resolution order is: CLI flag -> environment variable -> hard-coded default. Invalid environment variable values must cause the process to exit with a clear error message, not be silently ignored.

---

## AI-assisted development

This project was developed with the assistance of **Claude Sonnet 4.6** by Anthropic.

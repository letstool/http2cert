// Command http2cert is an HTTP API server that inspects X.509 certificates.
//
// # Endpoints
//
//	POST /api/v1/certinfo     - inspect a certificate
//	GET  /                    - Swagger UI (API documentation)
//	GET  /static/openapi.json - OpenAPI 3.1 spec
//	GET  /favicon.png         - favicon
//
// # Request (POST /api/v1/certinfo)
//
// Option A - live TLS socket:
//
//	{
//	  "socket": "example.com:443",   // domain:port | IPv4:port | [IPv6]:port
//	  "sni":    "example.com"        // optional, defaults to socket host
//	}
//
// Option B - raw certificate data (PEM or DER, single or chain):
//
//	{
//	  "raw_cert_data": "-----BEGIN CERTIFICATE-----\n..."
//	}
//
// # Response
//
//	{
//	  "result":  "SUCCESS",
//	  "source":  { "type": "SOCKET", "address": "93.184.216.34:443", ... },
//	  "answers": [ { "format": "PEM", "fingerprints": {...}, ... }, ... ]
//	}
//
// # Configuration
//
// Every option can be set via an environment variable; the corresponding
// command-line flag always takes precedence when explicitly provided.
//
//	Flag        Env var        Default          Description
//	-addr       LISTEN_ADDR    127.0.0.1:8080   listen address
//	-timeout    DIAL_TIMEOUT   10s              TLS dial+handshake timeout (Go duration: 5s, 1m, ...)
//	-json       LOG_JSON       false            emit structured JSON logs (true/false/1/0)
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/you/certinfo/internal/api"
)

// ---------------------------------------------------------------------------
//  Embedded static assets
// ---------------------------------------------------------------------------

//go:embed static/index.html
var indexHTML []byte

//go:embed static/favicon.png
var faviconPNG []byte

//go:embed static/openapi.json
var openapiJSON []byte

// ---------------------------------------------------------------------------
//  Static HTTP handlers
// ---------------------------------------------------------------------------

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML) //nolint:errcheck
}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Write(faviconPNG) //nolint:errcheck
}

func openapiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(openapiJSON) //nolint:errcheck
}

// ---------------------------------------------------------------------------
//  main
// ---------------------------------------------------------------------------

func main() {
	// Each flag reads its default from the matching environment variable.
	// An explicit flag on the command line always wins.
	// Precedence (highest to lowest): CLI flag > env var > built-in default.

	// -addr / LISTEN_ADDR
	defaultAddr := "127.0.0.1:8080"
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		defaultAddr = v
	}

	// -timeout / DIAL_TIMEOUT  (Go duration string: "10s", "1m30s", ...)
	defaultTimeout := 10 * time.Second
	if v := os.Getenv("DIAL_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "http2cert: invalid DIAL_TIMEOUT %q: %v\n", v, err)
			os.Exit(1)
		}
		defaultTimeout = d
	}

	// -json / LOG_JSON  (true / false / 1 / 0)
	defaultJSONLog := false
	if v := os.Getenv("LOG_JSON"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "http2cert: invalid LOG_JSON %q: must be true/false/1/0\n", v)
			os.Exit(1)
		}
		defaultJSONLog = b
	}

	addr    := flag.String("addr",    defaultAddr,    "listen address (env: LISTEN_ADDR)")
	timeout := flag.Duration("timeout", defaultTimeout, "TLS dial+handshake timeout, e.g. 10s (env: DIAL_TIMEOUT)")
	jsonLog := flag.Bool("json",      defaultJSONLog, "emit structured JSON logs instead of text (env: LOG_JSON)")
	flag.Parse()

	// -- Logger ---------------------------------------------------------------
	var logHandler slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if *jsonLog {
		logHandler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		logHandler = slog.NewTextHandler(os.Stdout, opts)
	}
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	// -- Routes ---------------------------------------------------------------
	apiHandler := api.NewHandler(logger)
	apiHandler.SetDialTimeout(*timeout)

	mux := http.NewServeMux()

	// API
	apiHandler.RegisterRoutes(mux)

	// Static assets
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("GET /favicon.png", faviconHandler)
	mux.HandleFunc("GET /openapi.json", openapiHandler)

	// -- Server ---------------------------------------------------------------
	srv := &http.Server{
		Addr:              *addr,
		Handler:           requestLogger(logger, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      *timeout + 15*time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// -- Graceful shutdown -----------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("http2cert starting", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
	logger.Info("stopped")
}

// ---------------------------------------------------------------------------
//  Request logger middleware
// ---------------------------------------------------------------------------

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		logger.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

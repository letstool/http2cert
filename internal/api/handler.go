package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/you/certinfo/pkg/certfetch"
	"github.com/you/certinfo/pkg/certinfo"
)

// -----------------------------------------------------------------------------
// Handler
// -----------------------------------------------------------------------------

// Handler is the HTTP handler for the certificate inspection API.
type Handler struct {
	logger         *slog.Logger
	fetcher        FetchFunc
	defaultTimeout time.Duration // server-wide default dial+handshake timeout
	maxTimeout     time.Duration // upper cap for per-request timeout
}

// FetchFunc is the TLS-fetch signature; injectable for tests.
type FetchFunc func(ctx context.Context, socket, sni string, opts *certfetch.Options) (*certfetch.Result, error)

// NewHandler creates a Handler with sane defaults (10 s timeout, 120 s cap).
func NewHandler(logger *slog.Logger) *Handler {
	return &Handler{
		logger:         logger,
		fetcher:        certfetch.Fetch,
		defaultTimeout: 10 * time.Second,
		maxTimeout:     120 * time.Second,
	}
}

// SetFetcher replaces the default TLS fetcher (useful for testing).
func (h *Handler) SetFetcher(f FetchFunc) { h.fetcher = f }

// SetDialTimeout sets the server-wide default timeout (used when the request
// does not include timeout).
func (h *Handler) SetDialTimeout(d time.Duration) {
	if d > 0 {
		h.defaultTimeout = d
	}
}

// RegisterRoutes attaches all routes to mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/certinfo", h.handleInspect)
}

// -----------------------------------------------------------------------------
// POST /cert - dispatcher
// -----------------------------------------------------------------------------

func (h *Handler) handleInspect(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ResultError, "failed to read request body: "+err.Error())
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ResultInvalidInput, "invalid JSON: "+err.Error())
		return
	}

	hasSocket := strings.TrimSpace(req.Socket) != ""
	hasRaw := strings.TrimSpace(req.RawCertData) != ""

	// -- Mutual exclusion -----------------------------------------------------
	if !hasSocket && !hasRaw {
		h.writeError(w, http.StatusBadRequest, ResultInvalidInput,
			`request must contain either "socket" or "raw_cert_data"`)
		return
	}
	if hasSocket && hasRaw {
		h.writeError(w, http.StatusBadRequest, ResultInvalidInput,
			`provide either "socket" or "raw_cert_data", not both`)
		return
	}

	// -- timeout is socket-only ----------------------------------------
	if hasRaw && req.Timeout != nil {
		h.writeError(w, http.StatusBadRequest, ResultInvalidInput,
			`"timeout" is only valid with "socket", not with "raw_cert_data"`)
		return
	}

	if hasSocket {
		h.handleSocket(w, r, &req)
	} else {
		h.handleRaw(w, r, &req)
	}
}

// -----------------------------------------------------------------------------
// Socket path
// -----------------------------------------------------------------------------

func (h *Handler) handleSocket(w http.ResponseWriter, r *http.Request, req *Request) {
	// -- Resolve effective timeout ---------------------------------------------
	timeout, err := h.resolveTimeout(req.Timeout)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ResultInvalidInput, err.Error())
		return
	}

	result, fetchErr := h.fetcher(r.Context(), req.Socket, req.SNI, &certfetch.Options{
		Timeout:            timeout,
		InsecureSkipVerify: true,
	})
	if fetchErr != nil {
		var dialErr *certfetch.DialError
		if errors.As(fetchErr, &dialErr) {
			switch dialErr.Kind {
			case "NOTFOUND":
				h.writeError(w, http.StatusBadGateway, ResultNotFound, fetchErr.Error())
			case "TLS_ERROR":
				h.writeError(w, http.StatusBadGateway, ResultTLSError, fetchErr.Error())
			default:
				h.writeError(w, http.StatusBadGateway, ResultError, fetchErr.Error())
			}
		} else {
			h.writeError(w, http.StatusBadRequest, ResultInvalidInput, fetchErr.Error())
		}
		return
	}

	answers, parseErr := parseCertSlice(result.Certificates)
	if parseErr != nil {
		h.writeError(w, http.StatusInternalServerError, ResultError, parseErr.Error())
		return
	}
	if len(answers) == 0 {
		h.writeError(w, http.StatusOK, ResultNoCertificates, "no certificates returned by server")
		return
	}

	h.logger.Info("socket inspect",
		"address", result.Address,
		"sni", result.SNI,
		"certs", len(answers),
		"timeout_s", int(timeout.Seconds()),
		"tls_version", tlsVersionName(result.TLSVersion),
	)

	writeJSON(w, http.StatusOK, Response{
		Result: ResultSuccess,
		Source: &SourceInfo{
			Type:           "SOCKET",
			Address:        result.Address,
			SNI:            result.SNI,
			Timeout: int(timeout.Seconds()),
			CertCount:      len(answers),
		},
		Answers: answers,
	})
}

// resolveTimeout returns the effective timeout to use for a socket request.
// If reqTimeout is nil -> server default.
// If out of [1, maxTimeout] -> INVALID_INPUT error.
func (h *Handler) resolveTimeout(reqTimeout *int) (time.Duration, error) {
	if reqTimeout == nil {
		return h.defaultTimeout, nil
	}
	v := *reqTimeout
	max := int(h.maxTimeout.Seconds())
	if v < 1 || v > max {
		return 0, fmt.Errorf("timeout must be between 1 and %d, got %d", max, v)
	}
	return time.Duration(v) * time.Second, nil
}

// -----------------------------------------------------------------------------
// Raw path
// -----------------------------------------------------------------------------

func (h *Handler) handleRaw(w http.ResponseWriter, r *http.Request, req *Request) {
	certs, format, err := decodeRawInput([]byte(req.RawCertData))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ResultInvalidInput, err.Error())
		return
	}
	if len(certs) == 0 {
		h.writeError(w, http.StatusOK, ResultNoCertificates, "no certificates found in raw_cert_data")
		return
	}

	answers, parseErr := parseCertSlice(certs)
	if parseErr != nil {
		h.writeError(w, http.StatusInternalServerError, ResultError, parseErr.Error())
		return
	}

	h.logger.Info("raw inspect", "format", format, "certs", len(answers))

	writeJSON(w, http.StatusOK, Response{
		Result: ResultSuccess,
		Source: &SourceInfo{
			Type:      "RAW",
			Format:    format,
			CertCount: len(answers),
		},
		Answers: answers,
	})
}

// -----------------------------------------------------------------------------
// PEM / DER decoder
// -----------------------------------------------------------------------------

func decodeRawInput(data []byte) ([]*x509.Certificate, string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, "", fmt.Errorf("raw_cert_data is empty")
	}

	if bytes.Contains(trimmed, []byte("-----BEGIN")) {
		certs, err := decodePEMChain(trimmed)
		if err != nil {
			return nil, "", fmt.Errorf("PEM decode: %w", err)
		}
		return certs, "PEM", nil
	}

	if trimmed[0] == 0x30 {
		cert, err := x509.ParseCertificate(trimmed)
		if err == nil {
			return []*x509.Certificate{cert}, "DER", nil
		}
	}

	if certs, err := decodePEMChain(trimmed); err == nil && len(certs) > 0 {
		return certs, "PEM", nil
	}

	return nil, "", fmt.Errorf("raw_cert_data is neither valid PEM nor DER")
}

func decodePEMChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseCertSlice converts raw x509 certificates into CertificateInfo entries.
// parseCertSlice converts raw x509 certificates into CertificateInfo entries.
func parseCertSlice(certs []*x509.Certificate) ([]*certinfo.CertificateInfo, error) {
	out := make([]*certinfo.CertificateInfo, 0, len(certs))
	for i, c := range certs {
		info, err := certinfo.ParseDER(c.Raw)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i+1, err)
		}
		out = append(out, info)
	}
	return out, nil
}


// -----------------------------------------------------------------------------
// Response helpers
// -----------------------------------------------------------------------------

func (h *Handler) writeError(w http.ResponseWriter, status int, code ResultCode, msg string) {
	h.logger.Warn("request error", "result", code, "message", msg)
	writeJSON(w, status, Response{
		Result:  code,
		Message: msg,
		Answers: []*certinfo.CertificateInfo{},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// -----------------------------------------------------------------------------
// Misc
// -----------------------------------------------------------------------------

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

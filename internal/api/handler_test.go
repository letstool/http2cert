package api_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/you/certinfo/internal/api"
	"github.com/you/certinfo/pkg/certfetch"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func postInspect(t *testing.T, h *api.Handler, body string) (int, *api.Response) {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certinfo", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	var resp api.Response
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v\nraw body: %s", err, rr.Body.String())
	}
	return rr.Code, &resp
}

func intPtr(n int) *int { return &n }

func mockFetcher(certs []*x509.Certificate) api.FetchFunc {
	return func(_ context.Context, socket, sni string, _ *certfetch.Options) (*certfetch.Result, error) {
		return &certfetch.Result{
			Certificates: certs, Address: socket, SNI: sni, TLSVersion: tls.VersionTLS13,
		}, nil
	}
}

func notFoundFetcher() api.FetchFunc {
	return func(_ context.Context, socket, _ string, _ *certfetch.Options) (*certfetch.Result, error) {
		return nil, &certfetch.DialError{
			Err: fmt.Errorf("no such host"), Kind: "NOTFOUND", Address: socket,
		}
	}
}

func parsePEMCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// -----------------------------------------------------------------------------
// Input validation
// -----------------------------------------------------------------------------

func TestInvalidJSON(t *testing.T) {
	_, resp := postInspect(t, api.NewHandler(noopLogger()), `{bad json}`)
	if resp.Result != api.ResultInvalidInput {
		t.Errorf("expected INVALID_INPUT, got %q", resp.Result)
	}
}

func TestMissingBothFields(t *testing.T) {
	_, resp := postInspect(t, api.NewHandler(noopLogger()), `{}`)
	if resp.Result != api.ResultInvalidInput {
		t.Errorf("expected INVALID_INPUT, got %q", resp.Result)
	}
}

func TestBothFieldsProvided(t *testing.T) {
	_, resp := postInspect(t, api.NewHandler(noopLogger()), `{"socket":"x:443","raw_cert_data":"abc"}`)
	if resp.Result != api.ResultInvalidInput {
		t.Errorf("expected INVALID_INPUT, got %q", resp.Result)
	}
}

func TestEmptyRawCertData(t *testing.T) {
	_, resp := postInspect(t, api.NewHandler(noopLogger()), `{"raw_cert_data":""}`)
	if resp.Result != api.ResultInvalidInput {
		t.Errorf("expected INVALID_INPUT for empty raw_cert_data, got %q", resp.Result)
	}
}

func TestGarbageRawCertData(t *testing.T) {
	_, resp := postInspect(t, api.NewHandler(noopLogger()), `{"raw_cert_data":"not a cert"}`)
	if resp.Result != api.ResultInvalidInput {
		t.Errorf("expected INVALID_INPUT for garbage, got %q", resp.Result)
	}
}

// -----------------------------------------------------------------------------
// timeout validation
// -----------------------------------------------------------------------------

func TestTimeoutWithRawCertData(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"raw_cert_data":   testPEM,
		"timeout": 5,
	})
	_, resp := postInspect(t, api.NewHandler(noopLogger()), string(body))
	if resp.Result != api.ResultInvalidInput {
		t.Errorf("timeout must be rejected with raw_cert_data, got %q", resp.Result)
	}
}

func TestTimeoutZero(t *testing.T) {
	h := api.NewHandler(noopLogger())
	h.SetFetcher(mockFetcher(nil)) // won't be reached
	body, _ := json.Marshal(map[string]any{"socket": "x:443", "timeout": 0})
	_, resp := postInspect(t, h, string(body))
	if resp.Result != api.ResultInvalidInput {
		t.Errorf("timeout 0 should be INVALID_INPUT, got %q", resp.Result)
	}
}

func TestTimeoutOverMax(t *testing.T) {
	h := api.NewHandler(noopLogger())
	h.SetFetcher(mockFetcher(nil))
	body, _ := json.Marshal(map[string]any{"socket": "x:443", "timeout": 999})
	_, resp := postInspect(t, h, string(body))
	if resp.Result != api.ResultInvalidInput {
		t.Errorf("timeout 999 should be INVALID_INPUT, got %q", resp.Result)
	}
}

func TestTimeoutValid(t *testing.T) {
	cert := parsePEMCert(t, testPEM)
	h := api.NewHandler(noopLogger())
	h.SetFetcher(mockFetcher([]*x509.Certificate{cert}))

	body, _ := json.Marshal(map[string]any{"socket": "example.com:443", "timeout": 30})
	_, resp := postInspect(t, h, string(body))
	if resp.Result != api.ResultSuccess {
		t.Fatalf("expected SUCCESS with valid timeout, got %q: %s", resp.Result, resp.Message)
	}
	if resp.Source.Timeout != 30 {
		t.Errorf("expected source.timeout=30, got %d", resp.Source.Timeout)
	}
}

func TestTimeoutDefaultUsedWhenAbsent(t *testing.T) {
	cert := parsePEMCert(t, testPEM)
	h := api.NewHandler(noopLogger())
	h.SetDialTimeout(15 * time.Second)
	h.SetFetcher(mockFetcher([]*x509.Certificate{cert}))

	_, resp := postInspect(t, h, `{"socket":"example.com:443"}`)
	if resp.Result != api.ResultSuccess {
		t.Fatalf("expected SUCCESS, got %q", resp.Result)
	}
	if resp.Source.Timeout != 15 {
		t.Errorf("expected source.timeout=15 (server default), got %d", resp.Source.Timeout)
	}
}

// -----------------------------------------------------------------------------
// Answer structure (flat)
// -----------------------------------------------------------------------------

func TestAnswerShape(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"raw_cert_data": testPEM})
	_, resp := postInspect(t, api.NewHandler(noopLogger()), string(body))

	if resp.Result != api.ResultSuccess {
		t.Fatalf("expected SUCCESS, got %q: %s", resp.Result, resp.Message)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].Fingerprints.SHA256 == "" {
		t.Error("fingerprints.sha256 must not be empty")
	}
}

// Verify the JSON shape via raw decode (no struct assumptions).
func TestAnswerJSONShape(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"raw_cert_data": testPEM})
	mux := http.NewServeMux()
	api.NewHandler(noopLogger()).RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certinfo", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	var raw map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	answers, ok := raw["answers"].([]any)
	if !ok || len(answers) == 0 {
		t.Fatal("answers must be a non-empty array")
	}
	first, ok := answers[0].(map[string]any)
	if !ok {
		t.Fatal("first answer must be a JSON object")
	}
	// fingerprints.sha256 must be present
	fingerprints, ok := first["fingerprints"].(map[string]any)
	if !ok {
		t.Fatal("fingerprints must be present and be an object")
	}
	if _, ok := fingerprints["sha256"]; !ok {
		t.Error("fingerprints.sha256 must be present")
	}
	// no cert_infos wrapper key should exist
	if _, ok := first["cert_infos"]; ok {
		t.Error("cert_infos wrapper must not exist - structure is flat")
	}
}

// -----------------------------------------------------------------------------
// Raw certificate
// -----------------------------------------------------------------------------

func TestRawPEMSingleCert(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"raw_cert_data": testPEM})
	_, resp := postInspect(t, api.NewHandler(noopLogger()), string(body))
	if resp.Result != api.ResultSuccess {
		t.Fatalf("expected SUCCESS, got %q: %s", resp.Result, resp.Message)
	}
	if resp.Source.Type != "RAW" {
		t.Errorf("source.type should be RAW, got %q", resp.Source.Type)
	}
	if resp.Source.Format != "PEM" {
		t.Errorf("source.format should be PEM, got %q", resp.Source.Format)
	}
}

func TestRawPEMChain(t *testing.T) {
	chain := testPEM + "\n" + testPEM
	body, _ := json.Marshal(map[string]string{"raw_cert_data": chain})
	_, resp := postInspect(t, api.NewHandler(noopLogger()), string(body))
	if resp.Result != api.ResultSuccess {
		t.Fatalf("expected SUCCESS, got %q: %s", resp.Result, resp.Message)
	}
	if len(resp.Answers) != 2 {
		t.Errorf("expected 2 certs in chain, got %d", len(resp.Answers))
	}
}

// -----------------------------------------------------------------------------
// Socket (mock fetcher - no real network)
// -----------------------------------------------------------------------------

func TestSocketSuccess(t *testing.T) {
	cert := parsePEMCert(t, testPEM)
	h := api.NewHandler(noopLogger())
	h.SetFetcher(mockFetcher([]*x509.Certificate{cert}))

	_, resp := postInspect(t, h, `{"socket":"example.com:443","sni":"example.com"}`)
	if resp.Result != api.ResultSuccess {
		t.Fatalf("expected SUCCESS, got %q: %s", resp.Result, resp.Message)
	}
	if resp.Source.Type != "SOCKET" {
		t.Errorf("expected SOCKET source, got %q", resp.Source.Type)
	}
}

func TestSocketChain(t *testing.T) {
	cert := parsePEMCert(t, testPEM)
	h := api.NewHandler(noopLogger())
	h.SetFetcher(mockFetcher([]*x509.Certificate{cert, cert}))

	_, resp := postInspect(t, h, `{"socket":"example.com:443"}`)
	if resp.Result != api.ResultSuccess {
		t.Fatalf("expected SUCCESS, got %q", resp.Result)
	}
	if len(resp.Answers) != 2 {
		t.Errorf("expected chain of 2, got %d", len(resp.Answers))
	}
}

func TestSocketNotFound(t *testing.T) {
	h := api.NewHandler(noopLogger())
	h.SetFetcher(notFoundFetcher())
	_, resp := postInspect(t, h, `{"socket":"does-not-exist.invalid:443"}`)
	if resp.Result != api.ResultNotFound {
		t.Errorf("expected NOTFOUND, got %q", resp.Result)
	}
}


// -----------------------------------------------------------------------------
// Fixture
// -----------------------------------------------------------------------------

const testPEM = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU4pBzXDfHVDANBgkqhkiG9w0BAQsFADAUMQswCQYDVQQGEwJV
UzEFMAMGA1UEAxMEdGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBa
MBQxCzAJBgNVBAYTAlVTMQUwAwYDVQQDEwR0ZXN0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5RJGQNMpPpMBbCTbDCMmGAoL3JJpk
2AVnT73SNy8V2QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCiAIZxLQNp7KJk3V+y
FpLMGQxsmY3lPx45AMt5fhY8WvZmHU1oNb/sLpkmJA+0EWMX1fLRqxZlLAiLn1+c
4FiPQxBn3VoSMnWLYxhKAKkpqvqxLkEe8H2BJ4mD9lPv6S1LT7EkHK/gSCUUqPB/
v4Vf3sEAD9lMl3UMj1hNJHk5jBfEkG9w1oGP/K7ESvK38JAkFjUfgQfRc+NVZH9
KJsJ7fZEcg1Fn4dGYp7YBCqBEEqW62kJHTBMKd9CGaOdIvCnWaiBOBLRv9VLzDz/
nf8rT5rBhyM7cHPHbFGVkAi7EgM7a6E56pKdj2L2nZCl1bujgVsivA0N6UwpPnY5
-----END CERTIFICATE-----`

// keep compiler happy
var _ = intPtr

package certinfo_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/you/certinfo/pkg/certinfo"
)

// -- Self-signed RSA 2048 test certificate (generated with Go's x509 package)
// openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout \
//   -days 3650 -nodes -subj "/CN=Test CA/O=Test Org/C=FR"
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

func TestParsePEM(t *testing.T) {
	info, err := certinfo.Parse([]byte(testPEM))
	if err != nil {
		t.Fatalf("Parse(PEM) returned error: %v", err)
	}
	if info.Format != "PEM" {
		t.Errorf("expected format PEM, got %q", info.Format)
	}
	if info.Version == 0 {
		t.Error("version should not be zero")
	}
	if info.SerialNumber == "" {
		t.Error("serial number should not be empty")
	}
	if info.SignatureAlgorithm == "" {
		t.Error("signature algorithm should not be empty")
	}
	if info.PublicKeyInfo.Algorithm == "" {
		t.Error("public key algorithm should not be empty")
	}
	if info.Fingerprints.SHA1 == "" || info.Fingerprints.SHA256 == "" {
		t.Error("fingerprints should not be empty")
	}
	t.Logf("Version: %d", info.Version)
	t.Logf("Subject: %s", info.Subject.Raw)
	t.Logf("Issuer:  %s", info.Issuer.Raw)
	t.Logf("PubKey:  %s %d bits", info.PublicKeyInfo.Algorithm, info.PublicKeyInfo.KeySize)
	t.Logf("SHA256:  %s", info.Fingerprints.SHA256)
}

func TestAutoDetectPEM(t *testing.T) {
	info, err := certinfo.Parse([]byte(testPEM))
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "PEM" {
		t.Errorf("auto-detect: expected PEM, got %q", info.Format)
	}
}

func TestJSONMarshal(t *testing.T) {
	info, err := certinfo.Parse([]byte(testPEM))
	if err != nil {
		t.Fatal(err)
	}
	b, merr := json.MarshalIndent(info, "", "  ")
	if merr != nil {
		t.Fatalf("JSON marshal error: %v", merr)
	}
	s := string(b)
	if !strings.Contains(s, `"format"`) {
		t.Error("JSON output should contain 'format' key")
	}
	if !strings.Contains(s, `"fingerprints"`) {
		t.Error("JSON output should contain 'fingerprints' key")
	}
	t.Log(s)
}

func TestInvalidInput(t *testing.T) {
	_, err := certinfo.Parse([]byte("not a certificate at all"))
	if err == nil {
		t.Error("expected error for invalid input")
	}
}

func TestEmptyInput(t *testing.T) {
	_, err := certinfo.Parse([]byte(""))
	if err == nil {
		t.Error("expected error for empty input")
	}
}

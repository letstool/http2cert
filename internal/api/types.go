package api

import "github.com/you/certinfo/pkg/certinfo"

// -----------------------------------------------------------------------------
// Result codes
// -----------------------------------------------------------------------------

// ResultCode is the top-level status of an API response.
type ResultCode string

const (
	// ResultSuccess means at least one certificate was parsed and returned.
	ResultSuccess ResultCode = "SUCCESS"

	// ResultInvalidInput means the request body was malformed or logically invalid
	// (e.g. both fields provided, neither provided, bad JSON, invalid timeout).
	ResultInvalidInput ResultCode = "INVALID_INPUT"

	// ResultNotFound means the host/IP could not be reached (DNS failure,
	// connection refused, network unreachable, timeout).
	ResultNotFound ResultCode = "NOTFOUND"

	// ResultTLSError means the TCP connection succeeded but the TLS handshake
	// failed before any certificate could be collected.
	ResultTLSError ResultCode = "TLS_ERROR"

	// ResultNoCertificates means the connection/parse succeeded but yielded zero
	// certificates (should be rare in practice).
	ResultNoCertificates ResultCode = "NO_CERTIFICATES"

	// ResultError is a generic internal server error.
	ResultError ResultCode = "ERROR"
)

// -----------------------------------------------------------------------------
// Request
// -----------------------------------------------------------------------------

// Request is the JSON body accepted by POST /inspect.
//
// Exactly one of Socket or RawCertData must be set.
//
//   - Socket: "<host>:<port>" where host is a domain name, IPv4, or bracketed
//     IPv6 address (e.g. "example.com:443", "1.2.3.4:8443", "[::1]:443").
//     The TLS handshake will be performed and the full certificate chain
//     returned.
//
//   - SNI: optional Server Name Indication to send during the TLS handshake.
//     If empty, the host part of Socket is used as SNI (standard behaviour).
//
//   - Timeout: optional per-request dial+handshake timeout (socket mode
//     only). Must be between 1 and 120. If omitted, the server default is used.
//     Ignored (and rejected) when raw_cert_data is used.
//
//   - RawCertData: PEM or DER bytes. Accepts single certificates and full PEM
//     chains. timeout must NOT be set alongside this field.
type Request struct {
	// Socket mode
	Socket         string `json:"socket,omitempty"`
	SNI            string `json:"sni,omitempty"`
	Timeout *int   `json:"timeout,omitempty"` // optional, socket only, 1-120

	// Raw mode
	RawCertData string `json:"raw_cert_data,omitempty"`
}

// -----------------------------------------------------------------------------
// Response
// -----------------------------------------------------------------------------

// Response is the JSON body returned for every request (including errors).
type Response struct {
	// Result is the machine-readable status code.
	Result ResultCode `json:"result"`

	// Message is a human-readable explanation (always set for non-SUCCESS codes).
	Message string `json:"message,omitempty"`

	// Source describes where the certificates came from.
	Source *SourceInfo `json:"source,omitempty"`

	// Answers contains one entry per parsed certificate, in chain order
	// (leaf first for TLS connections, document order for PEM chains).
	// Always present (empty array on error, never null).
	Answers []*certinfo.CertificateInfo `json:"answers"`
}

// SourceInfo describes the origin of the certificate data.
type SourceInfo struct {
	// Type is "SOCKET" or "RAW".
	Type string `json:"type"`

	// Address is the "host:port" dialed (SOCKET requests only).
	Address string `json:"address,omitempty"`

	// SNI is the server name sent in the ClientHello (SOCKET requests only).
	SNI string `json:"sni,omitempty"`

	// Timeout is the effective timeout that was applied (SOCKET only).
	Timeout int `json:"timeout,omitempty"`

	// Format is "PEM" or "DER" (RAW requests only).
	Format string `json:"format,omitempty"`

	// CertCount is the number of certificates found / returned.
	CertCount int `json:"cert_count"`
}

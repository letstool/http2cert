// Package certfetch dials a TLS endpoint and returns the raw certificate chain
// presented during the handshake. It uses only the Go standard library.
package certfetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Result holds the certificates and metadata returned by Fetch.
type Result struct {
	// Certificates is the peer chain in presentation order (leaf first).
	// It always contains at least one entry on success.
	Certificates []*x509.Certificate

	// Address is the "host:port" that was actually dialed.
	Address string

	// SNI is the server name sent in the ClientHello.
	SNI string

	// NegotiatedProtocol is the ALPN protocol agreed upon (e.g. "h2", "http/1.1").
	NegotiatedProtocol string

	// TLSVersion is the numeric TLS version (tls.VersionTLS12, etc.).
	TLSVersion uint16
}

// Options controls the behaviour of Fetch.
type Options struct {
	// Timeout for the full dial + handshake. Default: 10 s.
	Timeout time.Duration

	// InsecureSkipVerify disables certificate chain validation so we can
	// inspect expired, self-signed, or otherwise broken certificates.
	// Default: true (we want to see the cert, not validate it).
	InsecureSkipVerify bool
}

func defaultOptions() Options {
	return Options{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: true,
	}
}

// Fetch dials socket (format "<host>:<port>" including IPv6 "[::1]:443"),
// performs a TLS handshake with the given sni, and returns all certificates
// presented by the server.
//
// If sni is empty, the host part of socket is used (standard TLS behaviour).
//
// The function never validates the certificate chain - the goal is inspection,
// not authentication.
func Fetch(ctx context.Context, socket, sni string, opts *Options) (*Result, error) {
	if opts == nil {
		d := defaultOptions()
		opts = &d
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	host, port, err := parseSocket(socket)
	if err != nil {
		return nil, fmt.Errorf("invalid socket %q: %w", socket, err)
	}

	address := net.JoinHostPort(host, port)

	// Derive SNI: if not provided, use the host part (not an IP address).
	effectiveSNI := sni
	if effectiveSNI == "" {
		effectiveSNI = hostSNI(host)
	}

	tlsCfg := &tls.Config{
		ServerName:         effectiveSNI,
		InsecureSkipVerify: opts.InsecureSkipVerify, //nolint:gosec // intentional - inspection tool
		// Request full chain via standard TLS extension
		MinVersion: tls.VersionTLS10, //nolint:gosec // we accept all versions for inspection
	}

	dialCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    tlsCfg,
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, classifyDialError(err, host, address)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("TLS handshake succeeded but server sent no certificates")
	}

	return &Result{
		Certificates:       certs,
		Address:            address,
		SNI:                effectiveSNI,
		NegotiatedProtocol: state.NegotiatedProtocol,
		TLSVersion:         state.Version,
	}, nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// parseSocket splits a socket string into host and port.
// Accepts: "example.com:443", "1.2.3.4:443", "[::1]:443", "example.com" (no port -> "443").
func parseSocket(socket string) (host, port string, err error) {
	socket = strings.TrimSpace(socket)
	if socket == "" {
		return "", "", fmt.Errorf("empty socket")
	}

	// net.SplitHostPort handles IPv6 [::1]:port correctly.
	h, p, splitErr := net.SplitHostPort(socket)
	if splitErr != nil {
		// Maybe the user forgot the port - try appending :443
		h2, p2, err2 := net.SplitHostPort(socket + ":443")
		if err2 != nil {
			return "", "", splitErr // return the original error
		}
		return h2, p2, nil
	}

	if p == "" {
		p = "443"
	}
	return h, p, nil
}

// hostSNI returns the host suitable for SNI: strips brackets from IPv6,
// returns empty string for bare IP addresses (SNI must not be an IP).
func hostSNI(host string) string {
	// Strip IPv6 brackets if present
	h := strings.TrimPrefix(host, "[")
	h = strings.TrimSuffix(h, "]")

	ip := net.ParseIP(h)
	if ip != nil {
		// RFC 6066 S.3: SNI MUST NOT be an IP literal
		return ""
	}
	return h
}

// DialError wraps a connection error with a classification hint.
type DialError struct {
	Err     error
	Kind    string // "NOTFOUND" | "TLS_ERROR" | "ERROR"
	Address string
}

func (e *DialError) Error() string {
	return fmt.Sprintf("%s dialing %s: %v", e.Kind, e.Address, e.Err)
}

func (e *DialError) Unwrap() error { return e.Err }

func classifyDialError(err error, host, address string) *DialError {
	msg := strings.ToLower(err.Error())
	kind := "ERROR"
	switch {
	case strings.Contains(msg, "no such host"),
		strings.Contains(msg, "name resolution"),
		strings.Contains(msg, "nodename nor servname"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "context deadline exceeded"):
		kind = "NOTFOUND"
	case strings.Contains(msg, "tls"),
		strings.Contains(msg, "handshake"),
		strings.Contains(msg, "certificate"):
		kind = "TLS_ERROR"
	}
	_ = host
	return &DialError{Err: err, Kind: kind, Address: address}
}

// Package certinfo parses X.509 certificates (PEM or DER, auto-detected)
// and returns a rich JSON-serialisable structure equivalent to
// `openssl x509 -noout -text`.
//
// Only the Go standard library is used.
package certinfo

import (
	"bytes"
	"crypto/dsa"  //nolint:staticcheck // legacy key type still exists in the wild
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"   //nolint:gosec // fingerprint, not security-sensitive
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

// Parse accepts raw PEM or DER bytes, auto-detects the format, parses the
// first certificate found and returns a CertificateInfo ready to be marshalled
// to JSON.
func Parse(data []byte) (*CertificateInfo, error) {
	cert, format, err := decode(data)
	if err != nil {
		return nil, err
	}
	return build(cert, format)
}

// ParsePEM decodes and parses the first certificate block in a PEM stream.
func ParsePEM(data []byte) (*CertificateInfo, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PEM certificate: %w", err)
	}
	return build(cert, "PEM")
}

// ParseDER decodes and parses a DER-encoded certificate.
func ParseDER(data []byte) (*CertificateInfo, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}
	return build(cert, "DER")
}

// -----------------------------------------------------------------------------
// Detection + decoding
// -----------------------------------------------------------------------------

// decode auto-detects PEM vs DER and returns the parsed certificate.
// Detection heuristic: if the trimmed data starts with "-----" we try PEM
// first; otherwise we try DER first, then fall back to PEM.
func decode(data []byte) (*x509.Certificate, string, error) {
	trimmed := bytes.TrimSpace(data)

	if bytes.HasPrefix(trimmed, []byte("-----")) {
		// Looks like PEM
		block, _ := pem.Decode(trimmed)
		if block != nil {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, "", fmt.Errorf("parse PEM certificate: %w", err)
			}
			return c, "PEM", nil
		}
	}

	// Try DER (raw ASN.1 starts with 0x30 for SEQUENCE)
	if len(trimmed) > 0 && trimmed[0] == 0x30 {
		c, err := x509.ParseCertificate(trimmed)
		if err == nil {
			return c, "DER", nil
		}
	}

	// Last resort: try PEM decode on the original data
	block, _ := pem.Decode(trimmed)
	if block != nil {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse PEM certificate: %w", err)
		}
		return c, "PEM", nil
	}

	return nil, "", errors.New("data is neither valid PEM nor valid DER")
}

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

func build(c *x509.Certificate, format string) (*CertificateInfo, error) {
	rawPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))

	info := &CertificateInfo{
		Raw:                rawPEM,
		Format:             format,
		Version:            c.Version,
		SerialNumber:       colonHex(c.SerialNumber.Bytes()),
		SerialNumberDec:    c.SerialNumber.Text(10),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		Issuer:             parseDN(c.Issuer),
		Validity:           parseValidity(c),
		Subject:            parseDN(c.Subject),
		PublicKeyInfo:      parsePublicKey(c),
		Signature: SignatureInfo{
			Algorithm: c.SignatureAlgorithm.String(),
			Value:     hex.EncodeToString(c.Signature),
		},
		Fingerprints: parseFingerprints(c.Raw),
		IsSelfSigned: isSelfSigned(c),
		IsCA:         c.IsCA,
	}

	exts, err := parseExtensions(c)
	if err != nil {
		// non-fatal: include what we have, note the error
		_ = err
	}
	info.Extensions = exts

	return info, nil
}

// -----------------------------------------------------------------------------
// Distinguished Name
// -----------------------------------------------------------------------------

func parseDN(name pkix.Name) DistinguishedName {
	return DistinguishedName{
		Raw:                name.String(),
		CommonName:         name.CommonName,
		Organization:       nonEmpty(name.Organization),
		OrganizationalUnit: nonEmpty(name.OrganizationalUnit),
		Country:            nonEmpty(name.Country),
		Locality:           nonEmpty(name.Locality),
		Province:           nonEmpty(name.Province),
		StreetAddress:      nonEmpty(name.StreetAddress),
		PostalCode:         nonEmpty(name.PostalCode),
		SerialNumber:       name.SerialNumber,
		EmailAddress:       extractEmailsFromRDN(name),
	}
}

// extractEmailsFromRDN pulls emailAddress attributes from the raw RDN sequence.
func extractEmailsFromRDN(name pkix.Name) []string {
	oidEmailAddress := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	var emails []string
	for _, rdn := range name.Names {
		if rdn.Type.Equal(oidEmailAddress) {
			if s, ok := rdn.Value.(string); ok {
				emails = append(emails, s)
			}
		}
	}
	return emails
}

// -----------------------------------------------------------------------------
// Validity
// -----------------------------------------------------------------------------

func parseValidity(c *x509.Certificate) Validity {
	now := time.Now()
	daysLeft := int(c.NotAfter.Sub(now).Hours() / 24)
	return Validity{
		NotBefore:          c.NotBefore.UTC().Format(time.RFC3339),
		NotBeforeTimestamp: c.NotBefore.Unix(),
		NotAfter:           c.NotAfter.UTC().Format(time.RFC3339),
		NotAfterTimestamp:  c.NotAfter.Unix(),
		IsExpired:          now.After(c.NotAfter),
		DaysLeft:           daysLeft,
	}
}

// -----------------------------------------------------------------------------
// Public Key
// -----------------------------------------------------------------------------

func parsePublicKey(c *x509.Certificate) PublicKeyInfo {
	info := PublicKeyInfo{}

	// Raw SubjectPublicKeyInfo bytes (DER)
	info.PublicKey = hex.EncodeToString(c.RawSubjectPublicKeyInfo)

	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		info.Algorithm = "RSA"
		info.KeySize = pub.N.BitLen()
		info.Exponent = pub.E
		info.PublicKey = hex.EncodeToString(pub.N.Bytes())

	case *ecdsa.PublicKey:
		info.Algorithm = "EC"
		info.Curve = pub.Curve.Params().Name
		info.KeySize = pub.Curve.Params().BitSize
		// Uncompressed point encoding: 04 || X || Y
		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		raw := make([]byte, 1+2*byteLen)
		raw[0] = 0x04
		pub.X.FillBytes(raw[1 : 1+byteLen])
		pub.Y.FillBytes(raw[1+byteLen:])
		info.PublicKey = hex.EncodeToString(raw)

	case ed25519.PublicKey:
		info.Algorithm = "Ed25519"
		info.KeySize = 256
		info.PublicKey = hex.EncodeToString([]byte(pub))

	case *ecdh.PublicKey:
		info.Algorithm = "X25519/ECDH"
		info.PublicKey = hex.EncodeToString(pub.Bytes())

	case *dsa.PublicKey: //nolint:staticcheck
		info.Algorithm = "DSA"
		info.KeySize = pub.Y.BitLen()
		info.PublicKey = hex.EncodeToString(pub.Y.Bytes())

	default:
		info.Algorithm = fmt.Sprintf("unknown (%T)", pub)
	}

	return info
}

// -----------------------------------------------------------------------------
// Extensions
// -----------------------------------------------------------------------------

// Known OIDs not exported by crypto/x509
var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstr    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSubjectKeyID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidSAN            = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCRL            = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidAIA            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidCertPolicies   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtKeyUsages   = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidNameConstr     = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidOCSPNoCheck    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	oidSCTList        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func parseExtensions(c *x509.Certificate) (*Extensions, error) {
	if len(c.Extensions) == 0 {
		return nil, nil
	}

	exts := &Extensions{}

	// Index handled OIDs so we can catch unknowns
	handled := map[string]bool{}

	for _, ext := range c.Extensions {
		oidStr := ext.Id.String()

		switch {
		// -- Subject Key Identifier --------------------------------------------
		case ext.Id.Equal(oidSubjectKeyID):
			handled[oidStr] = true
			var keyID []byte
			if rest, err := asn1.Unmarshal(ext.Value, &keyID); err == nil && len(rest) == 0 {
				exts.SubjectKeyIdentifier = &SubjectKeyIdentifier{
					Critical: ext.Critical,
					KeyID:    colonHex(keyID),
				}
			}

		// -- Authority Key Identifier ------------------------------------------
		case ext.Id.Equal(oidAuthorityKeyID):
			handled[oidStr] = true
			aki := parseAKI(ext.Value, ext.Critical)
			exts.AuthorityKeyIdentifier = &aki

		// -- Key Usage ---------------------------------------------------------
		case ext.Id.Equal(oidExtKeyUsage):
			handled[oidStr] = true
			exts.KeyUsage = &KeyUsageExt{
				Critical: ext.Critical,
				Usages:   keyUsageStrings(c.KeyUsage),
			}

		// -- Extended Key Usage ------------------------------------------------
		case ext.Id.Equal(oidExtKeyUsages):
			handled[oidStr] = true
			exts.ExtendedKeyUsage = &ExtendedKeyUsageExt{
				Critical: ext.Critical,
				Usages:   extKeyUsageStrings(c.ExtKeyUsage, c.UnknownExtKeyUsage),
			}

		// -- Subject Alternative Name ------------------------------------------
		case ext.Id.Equal(oidSAN):
			handled[oidStr] = true
			san := &SubjectAlternativeName{Critical: ext.Critical}
			for _, d := range c.DNSNames {
				san.DNSNames = append(san.DNSNames, d)
			}
			for _, ip := range c.IPAddresses {
				san.IPAddresses = append(san.IPAddresses, ip.String())
			}
			for _, e := range c.EmailAddresses {
				san.EmailAddresses = append(san.EmailAddresses, e)
			}
			for _, u := range c.URIs {
				san.URIs = append(san.URIs, u.String())
			}
			exts.SubjectAlternativeName = san

		// -- Basic Constraints -------------------------------------------------
		case ext.Id.Equal(oidBasicConstr):
			handled[oidStr] = true
			maxLen := -1
			if c.MaxPathLen > 0 {
				maxLen = c.MaxPathLen
			}
			exts.BasicConstraints = &BasicConstraints{
				Critical:       ext.Critical,
				IsCA:           c.BasicConstraintsValid && c.IsCA,
				MaxPathLen:     maxLen,
				MaxPathLenZero: c.MaxPathLenZero,
			}

		// -- CRL Distribution Points -------------------------------------------
		case ext.Id.Equal(oidCRL):
			handled[oidStr] = true
			exts.CRLDistributionPoints = c.CRLDistributionPoints

		// -- Authority Info Access ---------------------------------------------
		case ext.Id.Equal(oidAIA):
			handled[oidStr] = true
			aia := &AuthorityInfoAccess{Critical: ext.Critical}
			for _, s := range c.OCSPServer {
				aia.OCSPServers = append(aia.OCSPServers, s)
			}
			for _, i := range c.IssuingCertificateURL {
				aia.CAIssuers = append(aia.CAIssuers, i)
			}
			exts.AuthorityInfoAccess = aia

		// -- Certificate Policies ----------------------------------------------
		case ext.Id.Equal(oidCertPolicies):
			handled[oidStr] = true
			exts.CertificatePolicies = parseCertPolicies(c.PolicyIdentifiers)

		// -- Name Constraints --------------------------------------------------
		case ext.Id.Equal(oidNameConstr):
			handled[oidStr] = true
			nc := parseNameConstraints(c, ext.Critical)
			exts.NameConstraints = &nc

		// -- OCSP No-Check -----------------------------------------------------
		case ext.Id.Equal(oidOCSPNoCheck):
			handled[oidStr] = true
			exts.OCSPNoCheck = true

		// -- SCT List (Certificate Transparency) -------------------------------
		case ext.Id.Equal(oidSCTList):
			handled[oidStr] = true
			exts.SCTList = parseSCTList(ext.Value)
		}
	}

	// Collect unhandled extensions
	for _, ext := range c.Extensions {
		oidStr := ext.Id.String()
		if !handled[oidStr] {
			exts.Unknown = append(exts.Unknown, UnknownExtension{
				OID:      oidStr,
				Critical: ext.Critical,
				Value:    hex.EncodeToString(ext.Value),
			})
		}
	}

	return exts, nil
}

// -- AKI parser ---------------------------------------------------------------

type rawAKI struct {
	KeyIdentifier             []byte         `asn1:"optional,tag:0"`
	AuthorityCertIssuer       asn1.RawValue  `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber *big.Int       `asn1:"optional,tag:2"`
}

func parseAKI(der []byte, critical bool) AuthorityKeyIdentifier {
	aki := AuthorityKeyIdentifier{Critical: critical}
	var raw rawAKI
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return aki
	}
	if len(raw.KeyIdentifier) > 0 {
		aki.KeyID = colonHex(raw.KeyIdentifier)
	}
	if raw.AuthorityCertSerialNumber != nil {
		aki.Serial = colonHex(raw.AuthorityCertSerialNumber.Bytes())
	}
	return aki
}

// -- Key Usage ----------------------------------------------------------------

func keyUsageStrings(ku x509.KeyUsage) []string {
	var out []string
	mapping := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Non Repudiation"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	for _, m := range mapping {
		if ku&m.bit != 0 {
			out = append(out, m.name)
		}
	}
	return out
}

// -- Extended Key Usage -------------------------------------------------------

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:                 "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "E-mail Protection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSEC End System",
	x509.ExtKeyUsageIPSECTunnel:                "IPSEC Tunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSEC User",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning:       "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:           "Microsoft Kernel Code Signing",
}

func extKeyUsageStrings(ekus []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier) []string {
	var out []string
	for _, eku := range ekus {
		if name, ok := extKeyUsageNames[eku]; ok {
			out = append(out, name)
		} else {
			out = append(out, fmt.Sprintf("unknown(%d)", eku))
		}
	}
	for _, oid := range unknown {
		out = append(out, oid.String())
	}
	return out
}

// -- Certificate Policies -----------------------------------------------------

var knownPolicyOIDs = map[string]string{
	"2.23.140.1.2.1": "CA/Browser Forum DV",
	"2.23.140.1.2.2": "CA/Browser Forum OV",
	"2.23.140.1.2.3": "CA/Browser Forum IV",
	"2.23.140.1.1":   "CA/Browser Forum EV",
	"1.3.6.1.5.5.7.2.1": "CPS Pointer",
	"1.3.6.1.5.5.7.2.2": "User Notice",
	"2.5.29.32.0":    "Any Policy",
}

func parseCertPolicies(oids []asn1.ObjectIdentifier) []CertificatePolicy {
	if len(oids) == 0 {
		return nil
	}
	var out []CertificatePolicy
	for _, oid := range oids {
		oidStr := oid.String()
		p := CertificatePolicy{OID: oidStr}
		if name, ok := knownPolicyOIDs[oidStr]; ok {
			p.Name = name
		}
		out = append(out, p)
	}
	return out
}

// -- Name Constraints ---------------------------------------------------------

func parseNameConstraints(c *x509.Certificate, critical bool) NameConstraints {
	nc := NameConstraints{Critical: critical}
	for _, d := range c.PermittedDNSDomains {
		nc.PermittedDNS = append(nc.PermittedDNS, d)
	}
	for _, d := range c.ExcludedDNSDomains {
		nc.ExcludedDNS = append(nc.ExcludedDNS, d)
	}
	for _, ip := range c.PermittedIPRanges {
		nc.PermittedIPs = append(nc.PermittedIPs, ip.String())
	}
	for _, ip := range c.ExcludedIPRanges {
		nc.ExcludedIPs = append(nc.ExcludedIPs, ip.String())
	}
	for _, e := range c.PermittedEmailAddresses {
		nc.PermittedEmails = append(nc.PermittedEmails, e)
	}
	for _, e := range c.ExcludedEmailAddresses {
		nc.ExcludedEmails = append(nc.ExcludedEmails, e)
	}
	for _, u := range c.PermittedURIDomains {
		nc.PermittedURIDomains = append(nc.PermittedURIDomains, u)
	}
	for _, u := range c.ExcludedURIDomains {
		nc.ExcludedURIDomains = append(nc.ExcludedURIDomains, u)
	}
	return nc
}

// -- SCT List -----------------------------------------------------------------
// We don't fully decode the TLS-encoded SCT list; we expose raw hex per entry
// so consumers can parse them with e.g. the ct-go library if needed.

func parseSCTList(der []byte) []string {
	// The extension value is an OCTET STRING wrapping a TLS-encoded SignedCertificateTimestampList
	var outer []byte
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return []string{hex.EncodeToString(der)}
	}
	if len(outer) < 2 {
		return []string{hex.EncodeToString(outer)}
	}
	// TLS list: 2-byte length prefix followed by 2-byte-length-prefixed SCTs
	listLen := int(outer[0])<<8 | int(outer[1])
	data := outer[2:]
	if len(data) < listLen {
		return []string{hex.EncodeToString(outer)}
	}
	var scts []string
	for len(data) >= 2 {
		sctLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if len(data) < sctLen {
			break
		}
		scts = append(scts, hex.EncodeToString(data[:sctLen]))
		data = data[sctLen:]
	}
	return scts
}

// -----------------------------------------------------------------------------
// Fingerprints
// -----------------------------------------------------------------------------

func parseFingerprints(raw []byte) Fingerprints {
	s1 := sha1.Sum(raw)   //nolint:gosec
	s256 := sha256.Sum256(raw)
	s512 := sha512.Sum512(raw)
	return Fingerprints{
		SHA1:   colonHex(s1[:]),
		SHA256: colonHex(s256[:]),
		SHA512: colonHex(s512[:]),
	}
}

// -----------------------------------------------------------------------------
// Self-signed detection
// -----------------------------------------------------------------------------

func isSelfSigned(c *x509.Certificate) bool {
	// Same subject and issuer bytes, and signature verifies against its own key
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// colonHex renders bytes as "aa:bb:cc:..." like OpenSSL does.
func colonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

func nonEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Ensure net is imported (used via c.IPAddresses which are net.IP)
var _ net.IP

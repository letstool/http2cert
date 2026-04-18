package certinfo

// CertificateInfo is the top-level JSON output structure.
// It mirrors what `openssl x509 -noout -text` displays.
type CertificateInfo struct {
	Raw                string             `json:"raw"`                 // PEM-encoded certificate
	Format             string             `json:"format"`              // "PEM" | "DER"
	Version            int                `json:"version"`             // X.509 version (1, 2, 3)
	SerialNumber       string             `json:"serial_number"`       // hex string
	SerialNumberDec    string             `json:"serial_number_dec"`   // decimal string
	SignatureAlgorithm string             `json:"signature_algorithm"`
	Issuer             DistinguishedName  `json:"issuer"`
	Validity           Validity           `json:"validity"`
	Subject            DistinguishedName  `json:"subject"`
	PublicKeyInfo      PublicKeyInfo      `json:"public_key_info"`
	Extensions         *Extensions        `json:"extensions,omitempty"`
	Signature          SignatureInfo      `json:"signature"`
	Fingerprints       Fingerprints       `json:"fingerprints"`
	IsSelfSigned       bool               `json:"is_self_signed"`
	IsCA               bool               `json:"is_ca"`
}

// DistinguishedName holds the parsed RDN fields of Subject / Issuer.
type DistinguishedName struct {
	Raw                string   `json:"raw"`                           // e.g. "CN=example.com,O=ACME,C=US"
	CommonName         string   `json:"common_name,omitempty"`         // CN
	Organization       []string `json:"organization,omitempty"`        // O
	OrganizationalUnit []string `json:"organizational_unit,omitempty"` // OU
	Country            []string `json:"country,omitempty"`             // C
	Locality           []string `json:"locality,omitempty"`            // L
	Province           []string `json:"province,omitempty"`            // ST
	StreetAddress      []string `json:"street_address,omitempty"`      // STREET
	PostalCode         []string `json:"postal_code,omitempty"`         // postalCode
	SerialNumber       string   `json:"serial_number,omitempty"`       // serialNumber
	EmailAddress       []string `json:"email_address,omitempty"`       // emailAddress
}

// Validity holds NotBefore / NotAfter timestamps.
type Validity struct {
	NotBefore          string `json:"not_before"`            // RFC3339
	NotBeforeTimestamp int64  `json:"not_before_timestamp"`  // Unix timestamp (seconds)
	NotAfter           string `json:"not_after"`             // RFC3339
	NotAfterTimestamp  int64  `json:"not_after_timestamp"`   // Unix timestamp (seconds)
	IsExpired          bool   `json:"is_expired"`
	DaysLeft           int    `json:"days_left"` // negative if expired
}

// PublicKeyInfo describes the subject public key.
type PublicKeyInfo struct {
	Algorithm  string `json:"algorithm"`            // RSA | EC | Ed25519 | DSA | ...
	KeySize    int    `json:"key_size_bits"`         // RSA/DSA: modulus bits; EC: curve field bits
	Curve      string `json:"curve,omitempty"`       // EC only: P-224 / P-256 / P-384 / P-521 / ...
	Exponent   int    `json:"exponent,omitempty"`    // RSA only
	PublicKey  string `json:"public_key_hex"`        // hex-encoded raw public key bytes
}

// Extensions holds all recognised X.509 v3 extensions.
type Extensions struct {
	SubjectKeyIdentifier        *SubjectKeyIdentifier        `json:"subject_key_identifier,omitempty"`
	AuthorityKeyIdentifier      *AuthorityKeyIdentifier      `json:"authority_key_identifier,omitempty"`
	KeyUsage                    *KeyUsageExt                 `json:"key_usage,omitempty"`
	ExtendedKeyUsage            *ExtendedKeyUsageExt         `json:"extended_key_usage,omitempty"`
	SubjectAlternativeName      *SubjectAlternativeName      `json:"subject_alternative_name,omitempty"`
	BasicConstraints            *BasicConstraints            `json:"basic_constraints,omitempty"`
	CRLDistributionPoints       []string                     `json:"crl_distribution_points,omitempty"`
	AuthorityInfoAccess         *AuthorityInfoAccess         `json:"authority_info_access,omitempty"`
	CertificatePolicies         []CertificatePolicy          `json:"certificate_policies,omitempty"`
	NameConstraints             *NameConstraints             `json:"name_constraints,omitempty"`
	OCSPNoCheck                 bool                         `json:"ocsp_no_check,omitempty"`
	SCTList                     []string                     `json:"signed_certificate_timestamps,omitempty"` // raw hex per SCT
	Unknown                     []UnknownExtension           `json:"unknown_extensions,omitempty"`
}

// SubjectKeyIdentifier holds the SKI extension value.
type SubjectKeyIdentifier struct {
	Critical bool   `json:"critical"`
	KeyID    string `json:"key_id"` // hex
}

// AuthorityKeyIdentifier holds the AKI extension.
type AuthorityKeyIdentifier struct {
	Critical bool     `json:"critical"`
	KeyID    string   `json:"key_id,omitempty"`    // hex
	Issuers  []string `json:"issuers,omitempty"`
	Serial   string   `json:"serial,omitempty"`    // hex
}

// KeyUsageExt lists the asserted key usages.
type KeyUsageExt struct {
	Critical bool     `json:"critical"`
	Usages   []string `json:"usages"`
}

// ExtendedKeyUsageExt lists OID names (or raw OIDs for unknown ones).
type ExtendedKeyUsageExt struct {
	Critical bool     `json:"critical"`
	Usages   []string `json:"usages"`
}

// SubjectAlternativeName lists all SAN entries.
type SubjectAlternativeName struct {
	Critical      bool     `json:"critical"`
	DNSNames      []string `json:"dns_names,omitempty"`
	IPAddresses   []string `json:"ip_addresses,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	URIs          []string `json:"uris,omitempty"`
}

// BasicConstraints holds the CA flag and optional path length.
type BasicConstraints struct {
	Critical              bool `json:"critical"`
	IsCA                  bool `json:"is_ca"`
	MaxPathLen            int  `json:"max_path_len"`            // -1 = not set
	MaxPathLenZero        bool `json:"max_path_len_zero"`       // explicit zero
}

// AuthorityInfoAccess holds OCSP and CA-Issuers URLs.
type AuthorityInfoAccess struct {
	Critical     bool     `json:"critical"`
	OCSPServers  []string `json:"ocsp_servers,omitempty"`
	CAIssuers    []string `json:"ca_issuers,omitempty"`
}

// CertificatePolicy holds one policy OID and its optional qualifiers.
type CertificatePolicy struct {
	OID        string   `json:"oid"`
	Name       string   `json:"name,omitempty"` // well-known OID friendly name
	Qualifiers []string `json:"qualifiers,omitempty"`
}

// NameConstraints holds permitted / excluded subtrees.
type NameConstraints struct {
	Critical           bool     `json:"critical"`
	PermittedDNS       []string `json:"permitted_dns,omitempty"`
	ExcludedDNS        []string `json:"excluded_dns,omitempty"`
	PermittedIPs       []string `json:"permitted_ips,omitempty"`
	ExcludedIPs        []string `json:"excluded_ips,omitempty"`
	PermittedEmails    []string `json:"permitted_emails,omitempty"`
	ExcludedEmails     []string `json:"excluded_emails,omitempty"`
	PermittedURIDomains []string `json:"permitted_uri_domains,omitempty"`
	ExcludedURIDomains  []string `json:"excluded_uri_domains,omitempty"`
}

// UnknownExtension preserves any extension the library does not specifically decode.
type UnknownExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	Value    string `json:"value_hex"`
}

// SignatureInfo holds the signature algorithm and the raw bytes.
type SignatureInfo struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value_hex"` // hex of DER signature bytes
}

// Fingerprints holds common hash digests of the DER-encoded certificate.
type Fingerprints struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

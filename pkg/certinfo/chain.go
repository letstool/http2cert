package certinfo

import (
	"encoding/pem"
	"fmt"
)

// ParseChain parses all PEM certificate blocks found in data and returns
// a slice of CertificateInfo in the order they appear.
// Useful for certificate chains or bundles.
func ParseChain(data []byte) ([]*CertificateInfo, error) {
	var results []*CertificateInfo
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
		info, err := ParseDER(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", len(results)+1, err)
		}
		info.Format = "PEM"
		results = append(results, info)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE PEM blocks found")
	}
	return results, nil
}

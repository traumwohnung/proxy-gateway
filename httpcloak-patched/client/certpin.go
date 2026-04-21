package client

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// PinType represents the type of certificate pin
type PinType int

const (
	// PinTypeSHA256 uses SHA256 hash of the certificate's Subject Public Key Info (SPKI)
	// This is the standard format used by HPKP and Chrome
	PinTypeSHA256 PinType = iota
	// PinTypeCertificate pins to the entire certificate
	PinTypeCertificate
)

// CertificatePin represents a pinned certificate or public key
type CertificatePin struct {
	// Type of pin (SHA256 of SPKI or full certificate)
	Type PinType

	// Hash is the pin value (base64 or hex encoded)
	Hash string

	// Host is the hostname this pin applies to (optional, empty = all hosts)
	Host string

	// IncludeSubdomains applies pin to subdomains as well
	IncludeSubdomains bool
}

// CertPinner handles certificate pinning verification
type CertPinner struct {
	pins        []*CertificatePin
	allowExpiry bool // Allow expired certificates if pinned
}

// NewCertPinner creates a new certificate pinner
func NewCertPinner() *CertPinner {
	return &CertPinner{
		pins:        make([]*CertificatePin, 0),
		allowExpiry: false,
	}
}

// AddPin adds a certificate pin
// hash should be base64-encoded SHA256 of the certificate's SPKI
// Example: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
func (p *CertPinner) AddPin(hash string, opts ...PinOption) *CertPinner {
	pin := &CertificatePin{
		Type: PinTypeSHA256,
		Hash: normalizeHash(hash),
	}

	for _, opt := range opts {
		opt(pin)
	}

	p.pins = append(p.pins, pin)
	return p
}

// AddPinFromCertFile loads a certificate from file and pins its public key
func (p *CertPinner) AddPinFromCertFile(certPath string, opts ...PinOption) error {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	return p.AddPinFromPEM(data, opts...)
}

// AddPinFromPEM adds a pin from PEM-encoded certificate data
func (p *CertPinner) AddPinFromPEM(pemData []byte, opts ...PinOption) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Calculate SPKI hash
	spkiHash := CalculateSPKIHash(cert)

	pin := &CertificatePin{
		Type: PinTypeSHA256,
		Hash: spkiHash,
	}

	for _, opt := range opts {
		opt(pin)
	}

	p.pins = append(p.pins, pin)
	return nil
}

// Verify checks if the certificate chain matches any pin
func (p *CertPinner) Verify(host string, certs []*x509.Certificate) error {
	if len(p.pins) == 0 {
		return nil // No pins configured, allow all
	}

	if len(certs) == 0 {
		return errors.New("no certificates provided")
	}

	// Find applicable pins for this host
	applicablePins := p.getPinsForHost(host)
	if len(applicablePins) == 0 {
		return nil // No pins for this host
	}

	// Check each certificate in chain against pins
	for _, cert := range certs {
		certHash := CalculateSPKIHash(cert)

		for _, pin := range applicablePins {
			if pin.Hash == certHash {
				return nil // Match found
			}
		}
	}

	return &CertPinError{
		Host:           host,
		ExpectedHashes: p.getPinHashes(applicablePins),
		ActualHashes:   getCertHashes(certs),
	}
}

// getPinsForHost returns pins applicable to the given host
func (p *CertPinner) getPinsForHost(host string) []*CertificatePin {
	var applicable []*CertificatePin

	for _, pin := range p.pins {
		if pin.Host == "" {
			// Global pin, applies to all hosts
			applicable = append(applicable, pin)
			continue
		}

		if pin.Host == host {
			applicable = append(applicable, pin)
			continue
		}

		// Check subdomain match
		if pin.IncludeSubdomains && strings.HasSuffix(host, "."+pin.Host) {
			applicable = append(applicable, pin)
		}
	}

	return applicable
}

func (p *CertPinner) getPinHashes(pins []*CertificatePin) []string {
	hashes := make([]string, len(pins))
	for i, pin := range pins {
		hashes[i] = pin.Hash
	}
	return hashes
}

func getCertHashes(certs []*x509.Certificate) []string {
	hashes := make([]string, len(certs))
	for i, cert := range certs {
		hashes[i] = CalculateSPKIHash(cert)
	}
	return hashes
}

// CalculateSPKIHash calculates the SHA256 hash of a certificate's SPKI
// Returns base64-encoded hash (HPKP format)
func CalculateSPKIHash(cert *x509.Certificate) string {
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(spkiHash[:])
}

// normalizeHash normalizes a hash string (removes prefixes, handles encoding)
func normalizeHash(hash string) string {
	// Remove common prefixes
	hash = strings.TrimPrefix(hash, "sha256/")
	hash = strings.TrimPrefix(hash, "sha256:")

	// If it looks like hex (64 chars, no +/= which are base64), convert to base64
	if len(hash) == 64 && !strings.ContainsAny(hash, "+/=") {
		decoded, err := hex.DecodeString(hash)
		if err == nil {
			return base64.StdEncoding.EncodeToString(decoded)
		}
	}

	return hash
}

// PinOption configures a certificate pin
type PinOption func(*CertificatePin)

// ForHost restricts the pin to a specific host
func ForHost(host string) PinOption {
	return func(p *CertificatePin) {
		p.Host = host
	}
}

// IncludeSubdomains applies the pin to subdomains as well
func IncludeSubdomains() PinOption {
	return func(p *CertificatePin) {
		p.IncludeSubdomains = true
	}
}

// CertPinError is returned when certificate pinning verification fails
type CertPinError struct {
	Host           string
	ExpectedHashes []string
	ActualHashes   []string
}

func (e *CertPinError) Error() string {
	return fmt.Sprintf("certificate pinning failed for %s: expected %v, got %v",
		e.Host, e.ExpectedHashes, e.ActualHashes)
}

// Clear removes all pins
func (p *CertPinner) Clear() {
	p.pins = make([]*CertificatePin, 0)
}

// HasPins returns true if any pins are configured
func (p *CertPinner) HasPins() bool {
	return len(p.pins) > 0
}

// GetPins returns all configured pins
func (p *CertPinner) GetPins() []*CertificatePin {
	return p.pins
}

// Package mitm implements F45: opt-in, user-installed-certificate TLS
// interception for phones and computers that choose to route through it —
// the same usage model as Surge/Burp/mitmproxy, not a silent, no-consent
// MITM. It is a different feature from the uprobe-based plaintext capture in
// internal/tlspeek (which needs nothing installed on the target device but
// only works for processes reachable on this host); this package instead
// terminates TLS itself, which only succeeds against a client that has
// explicitly installed and trusted the root CA generated here.
//
// A device that has NOT installed the CA gets a certificate error and its
// connection fails closed — there is no silent fallback to passing traffic
// through undecrypted, because that would defeat the point of a user
// consciously opting in.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA is a local root certificate authority whose private key never leaves
// this host, plus a cache of the per-hostname leaf certificates it has
// signed for the live proxy. Leaf certs all share one private key
// (regenerating an ECDSA key per host buys nothing — the key is never
// trusted on its own, only the leaf cert chaining back to the root is) so
// issuing one is just "sign a new cert", not "generate a new keypair".
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey

	leafKey *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*cachedLeaf
}

type cachedLeaf struct {
	certPEM []byte
	keyPEM  []byte
	expires time.Time
}

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 2 * 365 * 24 * time.Hour
)

// LoadOrCreate reads a root CA from dir (ca.pem / ca.key), generating and
// persisting a fresh one on first run. The key file is written 0600 — it is
// the one artifact that, if it leaked, would let someone else mint trusted
// certificates for any host against a device that installed this CA.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mitm: create CA dir: %w", err)
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	certBytes, certErr := os.ReadFile(certPath)
	keyBytes, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := fromPEM(certBytes, keyBytes)
		if err == nil {
			return ca, nil
		}
		// Fall through and regenerate rather than fail hard on a corrupt pair
		// — every device would need to reinstall the CA either way once one
		// half is unreadable, so there is nothing worth preserving.
	}

	cert, certDER, key, err := generateRootCA()
	if err != nil {
		return nil, err
	}
	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mitm: marshal CA key: %w", err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(keyPath, keyPEMBytes, 0o600); err != nil {
		return nil, fmt.Errorf("mitm: write CA key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEMBytes, 0o644); err != nil {
		return nil, fmt.Errorf("mitm: write CA cert: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate leaf key: %w", err)
	}
	return &CA{cert: cert, certPEM: certPEMBytes, key: key, leafKey: leafKey, cache: map[string]*cachedLeaf{}}, nil
}

func fromPEM(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("mitm: no PEM block in ca.pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("mitm: no PEM block in ca.key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse CA key: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate leaf key: %w", err)
	}
	return &CA{cert: cert, certPEM: certPEM, key: key, leafKey: leafKey, cache: map[string]*cachedLeaf{}}, nil
}

func generateRootCA() (*x509.Certificate, []byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mitm: generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mitm: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "BeeEye Local MITM Root",
			Organization: []string{"BeeEye (self-hosted, generated on this device)"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mitm: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mitm: parse generated CA cert: %w", err)
	}
	return cert, der, key, nil
}

// PEM returns the root CA certificate in PEM form — this is exactly what a
// phone or computer needs to download and install to start trusting this
// proxy (api.mitmCA serves it as-is with a mobile-install-friendly MIME type).
func (ca *CA) PEM() []byte { return ca.certPEM }

// Fingerprint is a short human-checkable identifier (SHA-256 of the DER
// cert, hex, first 16 chars) so a UI can show "does this match what your
// phone says it installed" without dumping the full certificate.
func (ca *CA) Fingerprint() string { return fingerprintHex(ca.cert.Raw) }

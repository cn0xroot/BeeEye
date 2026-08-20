package mitm

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

func fingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// IssueLeaf returns a certificate for host, signed by this CA, generating and
// caching one on first request. Called from tls.Config.GetCertificate during
// the handshake, so it must be safe for concurrent use and fast on a cache
// hit — both hold here: the mutex only guards the map, and cert generation
// (ECDSA sign, no keygen — see CA's doc comment) is a handful of
// milliseconds even on a cache miss.
func (ca *CA) IssueLeaf(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, fmt.Errorf("mitm: TLS ClientHello carried no SNI — cannot pick a certificate")
	}

	ca.mu.Lock()
	if c, ok := ca.cache[host]; ok && time.Now().Before(c.expires) {
		ca.mu.Unlock()
		cert, err := tls.X509KeyPair(c.certPEM, c.keyPEM)
		return &cert, err
	}
	ca.mu.Unlock()

	certPEM, keyPEM, expires, err := ca.signLeaf(host)
	if err != nil {
		return nil, err
	}

	ca.mu.Lock()
	ca.cache[host] = &cachedLeaf{certPEM: certPEM, keyPEM: keyPEM, expires: expires}
	ca.mu.Unlock()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return &cert, err
}

func (ca *CA) signLeaf(host string) (certPEM, keyPEM []byte, expires time.Time, err error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("mitm: leaf serial: %w", err)
	}
	now := time.Now()
	expires = now.Add(leafValidity)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              expires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &ca.leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("mitm: sign leaf for %s: %w", host, err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(ca.leafKey)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("mitm: marshal leaf key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, expires, nil
}

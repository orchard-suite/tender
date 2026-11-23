// Package testpki mints a root, an intermediate, and device certificates
// in memory, for tests.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// PKI is a root and the intermediate it signed.
type PKI struct {
	Root, Intermediate       *x509.Certificate
	RootKey, IntermediateKey crypto.Signer
}

var serial int64 = 100

func next() *big.Int { serial++; return big.NewInt(serial) }

// New mints a root and an intermediate named "Example Devices Issuing CA".
func New(t testing.TB) *PKI {
	t.Helper()
	rootKey := Key(t)
	root := sign(t, &x509.Certificate{
		SerialNumber:          next(),
		Subject:               pkix.Name{CommonName: "Example Devices Root CA", Organization: []string{"Example"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, rootKey, rootKey)
	intKey := Key(t)
	inter := sign(t, &x509.Certificate{
		SerialNumber:          next(),
		Subject:               pkix.Name{CommonName: "Example Devices Issuing CA", Organization: []string{"Example"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, root, intKey, rootKey)
	return &PKI{Root: root, Intermediate: inter, RootKey: rootKey, IntermediateKey: intKey}
}

// Key makes a P-256 key.
func Key(t testing.TB) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Device signs a client certificate for pub naming a device and a person.
func (p *PKI) Device(t testing.TB, pub crypto.PublicKey, device, email string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: next(),
		Subject:      pkix.Name{CommonName: device},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if email != "" {
		tmpl.EmailAddresses = []string{email}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.Intermediate, pub, p.IntermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Chain is a device certificate, its intermediate, and the root.
func (p *PKI) Chain(leaf *x509.Certificate) []*x509.Certificate {
	return []*x509.Certificate{leaf, p.Intermediate, p.Root}
}

func sign(t testing.TB, tmpl, parent *x509.Certificate, key, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

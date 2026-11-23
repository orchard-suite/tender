package identity_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/identity"
	"github.com/orchard-suite/tender/internal/testpki"
)

func TestIssuerMatches(t *testing.T) {
	pki := testpki.New(t)
	leaf := pki.Device(t, testpki.Key(t).Public(), "laptop-1", "", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	for want, match := range map[string]bool{
		"CN=Example Devices Issuing CA":            true,
		"cn=example devices issuing ca":            true,
		"O=Example, CN=Example Devices Issuing CA": true,
		"CN=Example Devices Issuing CA;O=Example":  true,
		"Example Devices Issuing CA":               true,
		"CN=Example Devices Root CA":               false,
		"CN=Example Devices Issuing CA, O=Acme":    false,
		"":                                         false,
	} {
		if got := identity.IssuerMatches(leaf, want); got != match {
			t.Errorf("IssuerMatches(%q) = %v, want %v", want, got, match)
		}
	}
}

func TestCandidatesPickTheNewestValidClientCert(t *testing.T) {
	pki := testpki.New(t)
	now := time.Now()
	old := pki.Device(t, testpki.Key(t).Public(), "laptop-1", "", now.Add(-2*time.Hour), now.Add(time.Hour))
	fresh := pki.Device(t, testpki.Key(t).Public(), "laptop-1", "", now.Add(-time.Hour), now.Add(time.Hour))
	expired := pki.Device(t, testpki.Key(t).Public(), "laptop-1", "", now.Add(-3*time.Hour), now.Add(-time.Minute))
	got := identity.Candidates([]*x509.Certificate{old, pki.Root, expired, fresh, pki.Intermediate}, "CN=Example Devices Issuing CA", now)
	if len(got) != 2 || got[0] != fresh || got[1] != old {
		t.Errorf("candidates = %v", got)
	}
}

func TestChainLeavesOutTheRoot(t *testing.T) {
	pki := testpki.New(t)
	leaf := pki.Device(t, testpki.Key(t).Public(), "laptop-1", "", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	chain := identity.BuildChain(leaf, []*x509.Certificate{pki.Root, pki.Intermediate, leaf})
	if len(chain) != 2 || chain[0] != leaf || chain[1] != pki.Intermediate {
		t.Errorf("chain = %v", chain)
	}
}

func TestKeyAndCertFiles(t *testing.T) {
	pki := testpki.New(t)
	dir := t.TempDir()
	store := &identity.FileStore{Key: filepath.Join(dir, "device.key"), Cert: filepath.Join(dir, "device.crt")}
	ref, signer, err := store.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf := pki.Device(t, signer.Public(), "laptop-1", "user@example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err := store.Install(ref, []*x509.Certificate{leaf, pki.Intermediate}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Identity{Key: store.Key, Cert: store.Cert, Issuer: "CN=Example Devices Issuing CA"}
	id, err := identity.Load(cfg, dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if id.Leaf().SerialNumber.Cmp(leaf.SerialNumber) != 0 || len(id.Chain) != 2 || id.Store != "file" {
		t.Errorf("identity = %+v", id)
	}
	if identity.PublicKeyID(id.Signer.Public()) != identity.PublicKeyID(leaf.PublicKey) {
		t.Error("the signer is not the certificate's key")
	}

	if _, err := identity.Load(config.Identity{Key: store.Key, Cert: store.Cert, Issuer: "CN=Someone Else"}, dir, time.Now()); err == nil {
		t.Error("a certificate from another issuer loaded")
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(store.Key, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := identity.Load(cfg, dir, time.Now()); err == nil {
			t.Error("a key file others can read was used")
		}
	}
}

func TestCSRNamesTheDeviceAndThePerson(t *testing.T) {
	key := testpki.Key(t)
	der, err := identity.CSR(key, "laptop-1", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "laptop-1" || len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "user@example.com" || len(csr.DNSNames) != 0 {
		t.Errorf("csr = %+v", csr.Subject)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Error(err)
	}
}

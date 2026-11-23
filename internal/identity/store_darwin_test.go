//go:build darwin && cgo

package identity

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/mackms"

	"github.com/orchard-suite/tender/internal/testpki"
)

// TestKeychainRoundTrip makes a key in the login keychain, keeps a
// certificate beside it, finds it again by issuer, signs with it, and
// removes both. It changes the person's keychain, so it runs only with
// TENDER_KEYCHAIN_TEST=1.
func TestKeychainRoundTrip(t *testing.T) {
	if os.Getenv("TENDER_KEYCHAIN_TEST") != "1" {
		t.Skip("set TENDER_KEYCHAIN_TEST=1 to use the login keychain")
	}
	s, err := osStore()
	if err != nil {
		t.Fatal(err)
	}
	ref, signer, err := s.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("key: %s", ref)
	km, _ := mackms.New(context.Background(), apiv1.Options{})
	t.Cleanup(func() {
		if err := km.DeleteKey(&apiv1.DeleteKeyRequest{Name: ref}); err != nil {
			t.Errorf("delete key: %v", err)
		}
	})

	pki := testpki.New(t)
	leaf := pki.Device(t, signer.Public(), "tender-keychain-test", "user@example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err := s.Install(ref, []*x509.Certificate{leaf, pki.Intermediate}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Remove(leaf); err != nil {
			t.Errorf("remove leaf: %v", err)
		}
		if err := s.Remove(pki.Intermediate); err != nil {
			t.Errorf("remove intermediate: %v", err)
		}
	})

	id, err := loadStore("CN=Example Devices Issuing CA", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if id.Leaf().SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("found serial %v, want %v", id.Leaf().SerialNumber, leaf.SerialNumber)
	}
	if len(id.Chain) != 2 {
		t.Errorf("chain has %d certificates, want leaf and intermediate", len(id.Chain))
	}
	if !samePublicKey(id.Signer.Public(), signer.Public()) {
		t.Error("the keychain opened another key")
	}
	if _, err := id.Signer.Sign(nil, make([]byte, 32), crypto.SHA256); err != nil {
		t.Errorf("sign: %v", err)
	}
}

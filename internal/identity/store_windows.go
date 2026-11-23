//go:build windows

package identity

import (
	"context"
	"crypto"
	"crypto/sha1" //nolint:gosec // the store names certificates by SHA-1 thumbprint
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/capi"
)

// HasStore says this operating system has a store for keys and
// certificates.
const HasStore = true

const (
	myStore = "capi:store-location=user;store=My"
	// Intermediates device management installs land in either CA store.
	userCA    = "capi:store-location=user;store=CA"
	machineCA = "capi:store-location=machine;store=CA"
)

// loadStore finds the identity issuer signed in CurrentUser\My and opens
// its key, wherever its provider keeps it: the TPM or the software store.
func loadStore(issuer string, now time.Time) (*Identity, error) {
	km, err := capi.New(context.Background(), apiv1.Options{})
	if err != nil {
		return nil, err
	}
	// The provider stays open: the signer's key handle is opened from it.
	mine, err := search(km, myStore)
	if err != nil {
		return nil, err
	}
	pool := append([]*x509.Certificate{}, mine...)
	for _, s := range []string{userCA, machineCA} {
		if more, err := search(km, s); err == nil {
			pool = append(pool, more...)
		}
	}
	var lastErr error
	for _, leaf := range Candidates(mine, issuer, now) {
		signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: thumbprintURI(leaf)})
		if err != nil {
			lastErr = err
			continue
		}
		return &Identity{Signer: signer, Chain: BuildChain(leaf, pool), Store: "certstore"}, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w with a usable key for issuer %q: %v", ErrNotFound, issuer, lastErr)
	}
	return nil, fmt.Errorf("%w in CurrentUser\\My for issuer %q", ErrNotFound, issuer)
}

func search(km *capi.CAPIKMS, store string) ([]*x509.Certificate, error) {
	resp, err := km.SearchCertificates(&apiv1.SearchCertificatesRequest{Name: store})
	if resp == nil {
		return nil, err
	}
	out := make([]*x509.Certificate, 0, len(resp.Results))
	for _, r := range resp.Results {
		out = append(out, r.Certificate)
	}
	return out, nil
}

func thumbprintURI(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw) //nolint:gosec // the store's own name for a certificate
	return myStore + ";sha1=" + hex.EncodeToString(sum[:])
}

// certStore makes keys with the TPM when the machine has one, and with the
// software key store when it does not. Neither lets the key be exported.
type certStore struct{}

func osStore() (Store, error) { return certStore{}, nil }

func (certStore) Name() string { return "certstore" }

func (certStore) CreateKey() (string, crypto.Signer, error) {
	var lastErr error
	for _, provider := range []string{capi.ProviderMSPCP, capi.ProviderMSKSP} {
		km, err := capi.New(context.Background(), apiv1.Options{URI: "capi:provider=" + provider})
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := km.CreateKey(&apiv1.CreateKeyRequest{Name: "capi:store-location=user", SignatureAlgorithm: apiv1.ECDSAWithSHA256})
		if err != nil {
			km.Close()
			lastErr = err
			continue
		}
		signer, err := km.CreateSigner(&resp.CreateSignerRequest)
		if err != nil {
			km.Close()
			return "", nil, err
		}
		return resp.Name, signer, nil
	}
	return "", nil, lastErr
}

func (certStore) Signer(ref string) (crypto.Signer, error) {
	km, err := capi.New(context.Background(), apiv1.Options{URI: providerOf(ref)})
	if err != nil {
		return nil, err
	}
	return km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: ref})
}

func (certStore) Install(ref string, chain []*x509.Certificate) error {
	km, err := capi.New(context.Background(), apiv1.Options{URI: providerOf(ref)})
	if err != nil {
		return err
	}
	defer km.Close()
	// ref is capi:provider=...;key=...;store-location=user: the key the
	// leaf belongs to.
	if err := km.StoreCertificate(&apiv1.StoreCertificateRequest{Name: ref + ";store=My", Certificate: chain[0]}); err != nil {
		return err
	}
	for _, c := range chain[1:] {
		if err := km.StoreCertificate(&apiv1.StoreCertificateRequest{Name: userCA + ";skip-find-certificate-key=true", Certificate: c}); err != nil {
			return err
		}
	}
	return nil
}

func (certStore) Remove(cert *x509.Certificate) error {
	km, err := capi.New(context.Background(), apiv1.Options{})
	if err != nil {
		return err
	}
	defer km.Close()
	return km.DeleteCertificate(&apiv1.DeleteCertificateRequest{Name: thumbprintURI(cert)})
}

func providerOf(ref string) string {
	for _, part := range strings.Split(strings.TrimPrefix(ref, "capi:"), ";") {
		if v, ok := strings.CutPrefix(part, "provider="); ok {
			return "capi:provider=" + v
		}
	}
	return ""
}

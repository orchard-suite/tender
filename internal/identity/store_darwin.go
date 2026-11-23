//go:build darwin && cgo

package identity

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/mackms"
)

// HasStore says this operating system has a store for keys and
// certificates.
const HasStore = true

// keyLabel names the keys enrollment makes in the keychain.
const keyLabel = "tender"

// loadStore finds the keychain identity issuer signed. The keychain cannot
// search by issuer, so Tender lists the certificates in the person's
// keychain search list with Apple's own security tool, picks the newest
// that matches, and opens its private key by the key's hash, wherever it
// lives: the login keychain or the Secure Enclave.
func loadStore(issuer string, now time.Time) (*Identity, error) {
	certs, err := keychainCertificates()
	if err != nil {
		return nil, err
	}
	km, err := mackms.New(context.Background(), apiv1.Options{})
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, leaf := range Candidates(certs, issuer, now) {
		signer, err := keychainSigner(km, leaf.PublicKey)
		if err != nil {
			lastErr = err
			continue
		}
		return &Identity{Signer: signer, Chain: BuildChain(leaf, certs), Store: "keychain"}, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w with a usable key for issuer %q: %v", ErrNotFound, issuer, lastErr)
	}
	return nil, fmt.Errorf("%w in the keychain for issuer %q", ErrNotFound, issuer)
}

func keychainSigner(km *mackms.MacKMS, pub crypto.PublicKey) (crypto.Signer, error) {
	hash, err := keychainHash(pub)
	if err != nil {
		return nil, err
	}
	// tag= with no value: a key device management made carries no tag.
	return km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: "mackms:hash=" + hex.EncodeToString(hash) + ";tag="})
}

// keychainCertificates lists every certificate in the person's keychain
// search list.
func keychainCertificates() ([]*x509.Certificate, error) {
	out, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("security find-certificate: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("security find-certificate: %w", err)
	}
	var certs []*x509.Certificate
	for rest := out; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

type keychainStore struct{ km *mackms.MacKMS }

func osStore() (Store, error) {
	km, err := mackms.New(context.Background(), apiv1.Options{})
	if err != nil {
		return nil, err
	}
	return &keychainStore{km: km}, nil
}

func (s *keychainStore) Name() string { return "keychain" }

// CreateKey makes the key in the Secure Enclave when this build may use
// it, and in the login keychain when it may not.
func (s *keychainStore) CreateKey() (string, crypto.Signer, error) {
	resp, err := s.km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "mackms:label=" + keyLabel + ";se=true",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	if err != nil {
		resp, err = s.km.CreateKey(&apiv1.CreateKeyRequest{
			Name:               "mackms:label=" + keyLabel,
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		})
	}
	if err != nil {
		return "", nil, err
	}
	signer, err := s.km.CreateSigner(&resp.CreateSignerRequest)
	if err != nil {
		return "", nil, err
	}
	return resp.Name, signer, nil
}

func (s *keychainStore) Signer(ref string) (crypto.Signer, error) {
	return s.km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: ref})
}

func (s *keychainStore) Install(_ string, chain []*x509.Certificate) error {
	for i, c := range chain {
		name := "mackms:label=" + keyLabel
		if i > 0 {
			name = "" // an intermediate takes its own common name
		}
		err := s.km.StoreCertificate(&apiv1.StoreCertificateRequest{Name: name, Certificate: c})
		var exists apiv1.AlreadyExistsError
		if err != nil && (i == 0 || !errors.As(err, &exists)) {
			return err
		}
	}
	return nil
}

func (s *keychainStore) Remove(cert *x509.Certificate) error {
	return s.km.DeleteCertificate(&apiv1.DeleteCertificateRequest{Name: "mackms:serial=" + cert.SerialNumber.String()})
}

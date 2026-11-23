package identity

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/softkms"
	"go.step.sm/crypto/pemutil"

	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/state"
)

// Store is where enrollment makes a key and keeps the certificate the
// authority signs for it.
type Store interface {
	// CreateKey makes a new key that never leaves the store. ref names it
	// for Signer and Install.
	CreateKey() (ref string, signer crypto.Signer, err error)
	// Signer opens a key CreateKey made.
	Signer(ref string) (crypto.Signer, error)
	// Install keeps a chain, leaf first, beside its key.
	Install(ref string, chain []*x509.Certificate) error
	// Remove deletes a certificate the store holds, never its key.
	Remove(cert *x509.Certificate) error
	// Name says what the store is, for people.
	Name() string
}

// StoreFor is the store enrollment uses: the files the config names, the
// operating system's store, or default files in the state directory.
func StoreFor(cfg config.Identity, stateDir string) (Store, error) {
	if cfg.Files() {
		return &FileStore{Key: config.ExpandHome(cfg.Key), Cert: config.ExpandHome(cfg.Cert)}, nil
	}
	if HasStore {
		return osStore()
	}
	key, cert := DefaultFiles(stateDir)
	return &FileStore{Key: key, Cert: cert}, nil
}

// FileStore keeps the key and the chain in two PEM files. The key file is
// readable by its user alone.
type FileStore struct{ Key, Cert string }

func (f *FileStore) Name() string { return "file" }

func (f *FileStore) CreateKey() (string, crypto.Signer, error) {
	resp, err := (&softkms.SoftKMS{}).CreateKey(&apiv1.CreateKeyRequest{
		Name:               f.Key,
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	if err != nil {
		return "", nil, err
	}
	signer, ok := resp.PrivateKey.(crypto.Signer)
	if !ok {
		return "", nil, errors.New("the new key cannot sign")
	}
	block, err := pemutil.Serialize(resp.PrivateKey)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(filepath.Dir(f.Key), 0o700); err != nil {
		return "", nil, err
	}
	if err := state.WriteFile(f.Key, pem.EncodeToMemory(block)); err != nil {
		return "", nil, err
	}
	return f.Key, signer, nil
}

func (f *FileStore) Signer(ref string) (crypto.Signer, error) {
	return fileSigner(ref)
}

func (f *FileStore) Install(_ string, chain []*x509.Certificate) error {
	var out []byte
	for _, c := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return writePublic(f.Cert, out)
}

// Remove does nothing: Install already replaced the file.
func (f *FileStore) Remove(*x509.Certificate) error { return nil }

func writePublic(path string, b []byte) error {
	if err := state.WriteFile(path, b); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}

func fileSigner(keyPath string) (crypto.Signer, error) {
	if runtime.GOOS != "windows" {
		st, err := os.Stat(keyPath)
		if err != nil {
			return nil, err
		}
		if st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s can be read by others (mode %v); only its user may read it", keyPath, st.Mode().Perm())
		}
	}
	km, err := softkms.New(context.Background(), apiv1.Options{})
	if err != nil {
		return nil, err
	}
	return km.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: keyPath})
}

func loadFiles(keyPath, certPath, issuer string, now time.Time) (*Identity, error) {
	certs, err := pemutil.ReadCertificateBundle(certPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s does not exist", ErrNotFound, certPath)
		}
		return nil, err
	}
	signer, err := fileSigner(keyPath)
	if err != nil {
		return nil, err
	}
	for _, leaf := range Candidates(certs, issuer, now) {
		if samePublicKey(signer.Public(), leaf.PublicKey) {
			return &Identity{Signer: signer, Chain: BuildChain(leaf, certs), Store: "file"}, nil
		}
	}
	return nil, fmt.Errorf("%w in %s for the key in %s", ErrNotFound, certPath, keyPath)
}

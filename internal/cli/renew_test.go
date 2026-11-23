package cli

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/identity"
	"github.com/orchard-suite/tender/internal/stepca"
	"github.com/orchard-suite/tender/internal/testpki"
)

type renewRig struct {
	e      *env
	cfg    *config.Config
	store  *identity.FileStore
	signer crypto.Signer
	pki    *testpki.PKI
	calls  int
}

// newRenewRig puts a certificate of life `life`, issued `age` ago, in key
// and cert files, and a step-ca that renews it.
func newRenewRig(t *testing.T, age, life time.Duration) *renewRig {
	t.Helper()
	dir := t.TempDir()
	g := &renewRig{pki: testpki.New(t)}
	g.store = &identity.FileStore{Key: filepath.Join(dir, "device.key"), Cert: filepath.Join(dir, "device.crt")}
	ref, signer, err := g.store.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	g.signer = signer
	now := time.Now()
	leaf := g.pki.Device(t, signer.Public(), "laptop-1", "user@example.com", now.Add(-age), now.Add(life-age))
	if err := g.store.Install(ref, []*x509.Certificate{leaf, g.pki.Intermediate}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.calls++
		if r.URL.Path != "/1.0/renew" || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(401)
			return
		}
		next := g.pki.Device(t, r.TLS.PeerCertificates[0].PublicKey, "laptop-1", "user@example.com", time.Now(), time.Now().Add(life))
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"certChain": []string{pemOf(next), pemOf(g.pki.Intermediate)}})
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	g.cfg = &config.Config{Identity: config.Identity{Key: g.store.Key, Cert: g.store.Cert}}
	g.e = &env{
		paths: config.Paths{Config: filepath.Join(dir, "tender.yaml"), State: dir, Logs: dir},
		log:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		out:   io.Discard,
		now:   time.Now,
	}
	rec := &stepca.Record{
		Authority: stepca.Authority, CA: srv.URL, Root: pemOf(srv.Certificate()),
		Store: "file", Key: ref, PublicKey: identity.PublicKeyID(signer.Public()),
	}
	if err := g.e.saveEnrollment(rec); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *renewRig) renew(t *testing.T, force bool) (bool, error) {
	t.Helper()
	keys := &keyring{cfg: g.cfg.Identity, stateDir: g.e.paths.State, now: time.Now}
	return g.e.renew(context.Background(), g.cfg, keys, force)
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func TestRenewsWhenAThirdOfLifeIsLeft(t *testing.T) {
	g := newRenewRig(t, 70*time.Hour, 90*time.Hour)
	before, _ := identity.Load(g.cfg.Identity, g.e.paths.State, time.Now())
	renewed, err := g.renew(t, false)
	if err != nil || !renewed || g.calls != 1 {
		t.Fatalf("renewed %v, err %v, calls %d", renewed, err, g.calls)
	}
	after, err := identity.Load(g.cfg.Identity, g.e.paths.State, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if after.Leaf().SerialNumber.Cmp(before.Leaf().SerialNumber) == 0 || !after.Leaf().NotAfter.After(before.Leaf().NotAfter) {
		t.Error("the renewed certificate was not kept")
	}
	rec, _ := g.e.loadEnrollment()
	if rec.Renewed.IsZero() {
		t.Error("the record does not say when it renewed")
	}
}

func TestDoesNotRenewEarly(t *testing.T) {
	g := newRenewRig(t, 10*time.Hour, 90*time.Hour)
	renewed, err := g.renew(t, false)
	if err != nil || renewed || g.calls != 0 {
		t.Fatalf("renewed %v, err %v, calls %d", renewed, err, g.calls)
	}
	if renewed, err = g.renew(t, true); err != nil || !renewed {
		t.Fatalf("--force: renewed %v, err %v", renewed, err)
	}
}

func TestNeverRenewsACertificateItDidNotEnroll(t *testing.T) {
	g := newRenewRig(t, 80*time.Hour, 90*time.Hour)
	// Device management replaces the certificate and key: the record no
	// longer names the key in use.
	rec, _ := g.e.loadEnrollment()
	rec.PublicKey = identity.PublicKeyID(testpki.Key(t).Public())
	if err := g.e.saveEnrollment(rec); err != nil {
		t.Fatal(err)
	}
	renewed, err := g.renew(t, false)
	if err != nil || renewed || g.calls != 0 {
		t.Fatalf("renewed %v, err %v, calls %d", renewed, err, g.calls)
	}
	if _, err := g.renew(t, true); err != errManaged || g.calls != 0 {
		t.Fatalf("--force on a managed certificate: err %v, calls %d", err, g.calls)
	}
}

package stepca_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/orchard-suite/tender/internal/identity"
	"github.com/orchard-suite/tender/internal/stepca"
	"github.com/orchard-suite/tender/internal/testpki"
)

// fakeIdP is an OIDC provider that hands out one code and redeems it once,
// checking PKCE.
type fakeIdP struct {
	mu        sync.Mutex
	srv       *httptest.Server
	challenge string
	nonce     string
	redirect  string
	token     string
}

func newIdP(t *testing.T) *fakeIdP {
	idp := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": idp.srv.URL + "/authorize",
			"token_endpoint":         idp.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != "the-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != idp.challenge ||
			r.Form.Get("redirect_uri") != idp.redirect || r.Form.Get("client_id") != "tender-client" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		claims, _ := json.Marshal(map[string]string{"email": "user@example.com", "nonce": idp.nonce, "aud": "tender-client"})
		idp.token = "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
		json.NewEncoder(w).Encode(map[string]string{"id_token": idp.token})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// browser plays the person: it checks the authorization request and
// follows the redirect back to Tender with a code.
func (idp *fakeIdP) browser(t *testing.T) stepca.Browser {
	return func(raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || !strings.HasPrefix(q.Get("redirect_uri"), "http://127.0.0.1:") {
			t.Errorf("authorization request = %v", q)
		}
		idp.mu.Lock()
		idp.challenge, idp.nonce, idp.redirect = q.Get("code_challenge"), q.Get("nonce"), q.Get("redirect_uri")
		idp.mu.Unlock()
		go func() {
			resp, err := http.Get(q.Get("redirect_uri") + "/?code=the-code&state=" + url.QueryEscape(q.Get("state")))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

// fakeCA is a step-ca that signs with an in-memory intermediate.
type fakeCA struct {
	srv  *httptest.Server
	pki  *testpki.PKI
	idp  *fakeIdP
	life time.Duration
}

func newCA(t *testing.T, idp *fakeIdP) *fakeCA {
	ca := &fakeCA{pki: testpki.New(t), idp: idp, life: 24 * time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /root/{fp}", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"ca": pemOf(ca.srv.Certificate())})
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"provisioners": []map[string]string{
			{"type": "JWK", "name": "admin"},
			{"type": "OIDC", "name": "people", "clientID": "tender-client", "configurationEndpoint": idp.srv.URL + "/.well-known/openid-configuration"},
		}})
	})
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, OTT string }
		json.NewDecoder(r.Body).Decode(&req)
		if req.OTT == "" || req.OTT != idp.token {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"message": "the token is not valid"})
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			w.WriteHeader(400)
			return
		}
		ca.issue(t, w, csr.PublicKey, csr.Subject, csr.EmailAddresses)
	})
	mux.HandleFunc("POST /1.0/renew", func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"message": "no client certificate"})
			return
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca.pki.Root)
		inter := x509.NewCertPool()
		for _, c := range r.TLS.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		leaf := r.TLS.PeerCertificates[0]
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}
		ca.issue(t, w, leaf.PublicKey, leaf.Subject, leaf.EmailAddresses)
	})
	ca.srv = httptest.NewUnstartedServer(mux)
	ca.srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	ca.srv.StartTLS()
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) issue(t *testing.T, w http.ResponseWriter, pub any, subject pkix.Name, emails []string) {
	leaf := ca.pki.Device(t, pub, subject.CommonName, strings.Join(emails, ""), time.Now().Add(-time.Minute), time.Now().Add(ca.life))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"crt":       pemOf(leaf),
		"ca":        pemOf(ca.pki.Intermediate),
		"certChain": []string{pemOf(leaf), pemOf(ca.pki.Intermediate)},
	})
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func TestEnrollThenRenew(t *testing.T) {
	ctx := context.Background()
	idp := newIdP(t)
	ca := newCA(t, idp)

	client, err := stepca.New(ctx, ca.srv.URL, fingerprint(ca.srv.Certificate()), "")
	if err != nil {
		t.Fatal(err)
	}
	prov, err := client.OIDCProvisioner(ctx, "")
	if err != nil || prov.Name != "people" {
		t.Fatalf("provisioner = %+v, %v", prov, err)
	}
	signIn, err := client.SignInOIDC(ctx, prov, idp.browser(t))
	if err != nil {
		t.Fatal(err)
	}
	if signIn.Email != "user@example.com" {
		t.Errorf("email = %q", signIn.Email)
	}

	dir := t.TempDir()
	store := &identity.FileStore{Key: filepath.Join(dir, "device.key"), Cert: filepath.Join(dir, "device.crt")}
	ref, signer, err := store.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := identity.CSR(signer, "laptop-1", signIn.Email)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := client.Sign(ctx, csr, signIn.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if chain[0].Subject.CommonName != "laptop-1" || chain[0].EmailAddresses[0] != "user@example.com" || len(chain) != 2 {
		t.Errorf("signed = %v %v (%d certs)", chain[0].Subject, chain[0].EmailAddresses, len(chain))
	}
	if err := store.Install(ref, chain); err != nil {
		t.Fatal(err)
	}

	// A client made from the saved root, as the agent makes it later.
	again, err := stepca.New(ctx, ca.srv.URL, "", client.RootPEM())
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := again.Renew(ctx, chain, signer)
	if err != nil {
		t.Fatal(err)
	}
	if renewed[0].SerialNumber.Cmp(chain[0].SerialNumber) == 0 {
		t.Error("renewal returned the same certificate")
	}
	if identity.PublicKeyID(renewed[0].PublicKey) != identity.PublicKeyID(signer.Public()) {
		t.Error("renewal changed the key")
	}
}

func TestWrongFingerprintIsRefused(t *testing.T) {
	ca := newCA(t, newIdP(t))
	if _, err := stepca.New(context.Background(), ca.srv.URL, strings.Repeat("ab", 32), ""); err == nil {
		t.Error("a root that does not match the fingerprint was trusted")
	}
}

func TestSignWithoutTheSignInIsRefused(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t, newIdP(t))
	client, err := stepca.New(ctx, ca.srv.URL, fingerprint(ca.srv.Certificate()), "")
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := identity.CSR(testpki.Key(t), "laptop-1", "user@example.com")
	_, err = client.Sign(ctx, csr, "forged")
	if err == nil || !strings.Contains(err.Error(), "the token is not valid") {
		t.Errorf("err = %v", err)
	}
}

func TestDueForRenewalAtAThirdOfLifeLeft(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * 24 * time.Hour)}
	for days, due := range map[int]bool{0: false, 59: false, 61: true, 89: true} {
		if got := stepca.DueForRenewal(leaf, start.Add(time.Duration(days)*24*time.Hour)); got != due {
			t.Errorf("day %d: due = %v, want %v", days, got, due)
		}
	}
}

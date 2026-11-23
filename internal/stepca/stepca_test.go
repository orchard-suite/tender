package stepca_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"github.com/orchard-suite/tender/internal/stepca/stepcatest"
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

func newCA(t *testing.T, idp *fakeIdP) *stepcatest.CA {
	ca := stepcatest.New(t)
	ca.Configuration = idp.srv.URL + "/.well-known/openid-configuration"
	return ca
}

func TestEnrollThenRenew(t *testing.T) {
	ctx := context.Background()
	idp := newIdP(t)
	ca := newCA(t, idp)

	client, err := stepca.New(ctx, ca.Server.URL, ca.Fingerprint(), "")
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
	ca.IDToken = signIn.IDToken

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
	again, err := stepca.New(ctx, ca.Server.URL, "", client.RootPEM())
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := again.Renew(ctx, chain, signer)
	if err != nil {
		t.Fatalf("%v (refusals: %v)", err, ca.Refusals())
	}
	if renewed[0].SerialNumber.Cmp(chain[0].SerialNumber) == 0 {
		t.Error("renewal returned the same certificate")
	}
	if identity.PublicKeyID(renewed[0].PublicKey) != identity.PublicKeyID(signer.Public()) {
		t.Error("renewal changed the key")
	}
	if ca.Renewals() != 1 {
		t.Errorf("renewals = %d", ca.Renewals())
	}
}

func TestRenewWithAnRSAKey(t *testing.T) {
	ca := newCA(t, newIdP(t))
	client, err := stepca.New(context.Background(), ca.Server.URL, ca.Fingerprint(), "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsaKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf := ca.Issue(t, key.Public(), "laptop-1", "user@example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if _, err := client.Renew(context.Background(), []*x509.Certificate{leaf, ca.PKI.Intermediate}, key); err != nil {
		t.Fatalf("%v (refusals: %v)", err, ca.Refusals())
	}
}

func TestRenewalWithoutATokenIsRefused(t *testing.T) {
	ca := newCA(t, newIdP(t))
	req, _ := http.NewRequest(http.MethodPost, ca.Server.URL+"/1.0/renew", nil)
	resp, err := ca.Server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || ca.Renewals() != 0 {
		t.Errorf("a renewal with no token got %d", resp.StatusCode)
	}
}

func TestRenewalSignedByAnotherKeyIsRefused(t *testing.T) {
	ca := newCA(t, newIdP(t))
	client, err := stepca.New(context.Background(), ca.Server.URL, ca.Fingerprint(), "")
	if err != nil {
		t.Fatal(err)
	}
	key := testpki.Key(t)
	leaf := ca.Issue(t, key.Public(), "laptop-1", "user@example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, err = client.Renew(context.Background(), []*x509.Certificate{leaf, ca.PKI.Intermediate}, testpki.Key(t))
	if err == nil || !strings.Contains(err.Error(), "bad signature") || ca.Renewals() != 0 {
		t.Errorf("a token from another key renewed: %v", err)
	}
}

func TestExpiredCertificateCanStillRenew(t *testing.T) {
	ca := newCA(t, newIdP(t))
	client, err := stepca.New(context.Background(), ca.Server.URL, ca.Fingerprint(), "")
	if err != nil {
		t.Fatal(err)
	}
	key := testpki.Key(t)
	leaf := ca.Issue(t, key.Public(), "laptop-1", "user@example.com", time.Now().Add(-50*time.Minute), time.Now().Add(-10*time.Minute))
	if _, err := client.Renew(context.Background(), []*x509.Certificate{leaf, ca.PKI.Intermediate}, key); err != nil {
		t.Fatalf("%v (refusals: %v)", err, ca.Refusals())
	}
}

func TestWrongFingerprintIsRefused(t *testing.T) {
	ca := newCA(t, newIdP(t))
	if _, err := stepca.New(context.Background(), ca.Server.URL, strings.Repeat("ab", 32), ""); err == nil {
		t.Error("a root that does not match the fingerprint was trusted")
	}
}

func TestSignWithoutTheSignInIsRefused(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t, newIdP(t))
	client, err := stepca.New(ctx, ca.Server.URL, ca.Fingerprint(), "")
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

func rsaKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }

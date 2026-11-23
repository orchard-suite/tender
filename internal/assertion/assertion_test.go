package assertion_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/orchard-suite/tender/internal/assertion"
	"github.com/orchard-suite/tender/internal/testpki"
)

var b64 = base64.RawURLEncoding

// parse splits a compact JWS and checks its signature against the leaf.
func parse(t *testing.T, tok string) (assertion.Header, assertion.Claims) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 parts, got %d", len(parts))
	}
	var h assertion.Header
	var c assertion.Claims
	decode(t, parts[0], &h)
	decode(t, parts[1], &c)
	der, err := base64.StdEncoding.DecodeString(h.X5C[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if len(sig) != 64 {
			t.Fatalf("ES256 signature is %d bytes, want 64", len(sig))
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			t.Fatal("ES256 signature does not verify")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			t.Fatalf("PS256 signature does not verify: %v", err)
		}
	}
	return h, c
}

func decode(t *testing.T, part string, v any) {
	t.Helper()
	b, err := b64.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestClaimsBindTheRequest(t *testing.T) {
	pki := testpki.New(t)
	key := testpki.Key(t)
	leaf := pki.Device(t, key.Public(), "laptop-1", "user@example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	now := time.Unix(1_800_000_000, 0)
	u, _ := url.Parse("https://muster.example.com:8443/tender/v1/readers/muster?x=1#frag")
	body := []byte(`{"reader":"muster"}`)

	tok, err := assertion.Sign(assertion.Key{Signer: key, Chain: pki.Chain(leaf)}, "post", u, body, now)
	if err != nil {
		t.Fatal(err)
	}
	h, c := parse(t, tok)

	if h.Alg != "ES256" || h.Typ != "tender+jwt" {
		t.Errorf("header = %+v", h)
	}
	if len(h.X5C) != 2 {
		t.Fatalf("x5c holds %d certificates, want leaf and intermediate without the root", len(h.X5C))
	}
	inter, _ := base64.StdEncoding.DecodeString(h.X5C[1])
	if string(inter) != string(pki.Intermediate.Raw) {
		t.Error("x5c[1] is not the intermediate")
	}
	sum := sha256.Sum256(body)
	want := assertion.Claims{
		Aud: "https://muster.example.com:8443",
		Htm: "POST",
		Htu: "https://muster.example.com:8443/tender/v1/readers/muster",
		Bh:  b64.EncodeToString(sum[:]),
		Iat: now.Unix(),
		Exp: now.Unix() + 300,
		Jti: c.Jti,
	}
	if c != want {
		t.Errorf("claims = %+v\nwant     %+v", c, want)
	}
	if jti, err := b64.DecodeString(c.Jti); err != nil || len(jti) != 16 {
		t.Errorf("jti %q is not 16 random bytes", c.Jti)
	}

	tok2, _ := assertion.Sign(assertion.Key{Signer: key, Chain: pki.Chain(leaf)}, "post", u, body, now)
	if _, c2 := parse(t, tok2); c2.Jti == c.Jti {
		t.Error("two assertions share a jti")
	}
}

func TestEmptyBodyHashesEmptyBytes(t *testing.T) {
	pki := testpki.New(t)
	key := testpki.Key(t)
	leaf := pki.Device(t, key.Public(), "laptop-1", "", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	u, _ := url.Parse("https://muster.example.com/tender/v1/readers/muster")
	tok, err := assertion.Sign(assertion.Key{Signer: key, Chain: []*x509.Certificate{leaf, pki.Intermediate}}, "GET", u, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, c := parse(t, tok)
	empty := sha256.Sum256(nil)
	if c.Bh != b64.EncodeToString(empty[:]) || c.Htm != "GET" || c.Aud != "https://muster.example.com" {
		t.Errorf("claims = %+v", c)
	}
}

func TestRSAKeySignsPS256(t *testing.T) {
	pki := testpki.New(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := pki.Device(t, key.Public(), "laptop-1", "", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	u, _ := url.Parse("https://muster.example.com/tender/v1/readers/muster")
	tok, err := assertion.Sign(assertion.Key{Signer: key, Chain: pki.Chain(leaf)}, "GET", u, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := parse(t, tok); h.Alg != "PS256" {
		t.Errorf("alg = %s, want PS256", h.Alg)
	}
}

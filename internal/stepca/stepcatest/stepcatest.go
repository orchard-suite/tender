// Package stepcatest is a step-ca for tests: it serves the root, the
// provisioners, /1.0/sign, and /1.0/renew, signing from an in-memory
// intermediate. It checks a renewal's bearer token as step-ca does, and
// asks for no client certificate, as a proxy that ends TLS would not pass
// one on.
package stepcatest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/orchard-suite/tender/internal/stepca"
	"github.com/orchard-suite/tender/internal/testpki"
)

// CA is the fake authority.
type CA struct {
	Server *httptest.Server
	PKI    *testpki.PKI
	// Life is how long a certificate it signs lives.
	Life time.Duration
	// IDToken is the one-time token /1.0/sign takes; empty takes none.
	IDToken string
	// Configuration is the OIDC provisioner's configuration endpoint.
	Configuration string

	mu       sync.Mutex
	renewals int
	refusals []string
	seen     map[string]bool
}

// New starts a fake step-ca. It closes when the test ends.
func New(t testing.TB) *CA {
	t.Helper()
	ca := &CA{PKI: testpki.New(t), Life: 24 * time.Hour, seen: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /root/{fp}", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"ca": PEM(ca.Server.Certificate())})
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"provisioners": []map[string]string{
			{"type": "JWK", "name": "admin"},
			{"type": "OIDC", "name": "people", "clientID": "tender-client", "configurationEndpoint": ca.Configuration},
		}})
	})
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, OTT string }
		json.NewDecoder(r.Body).Decode(&req)
		if req.OTT == "" || req.OTT != ca.IDToken {
			ca.refuse(w, http.StatusUnauthorized, "the token is not valid")
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			ca.refuse(w, http.StatusBadRequest, "no csr")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			ca.refuse(w, http.StatusBadRequest, "bad csr")
			return
		}
		ca.issue(t, w, csr.PublicKey, csr.Subject, csr.EmailAddresses)
	})
	mux.HandleFunc("POST /1.0/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ca.refuse(w, http.StatusBadRequest, "a client certificate was sent; the proxy would have dropped it")
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			ca.refuse(w, http.StatusBadRequest, "missing client certificate")
			return
		}
		leaf, err := ca.checkRenewToken(tok, ca.Server.URL+"/1.0/renew", time.Now())
		if err != nil {
			ca.refuse(w, http.StatusUnauthorized, "error validating renew token: "+err.Error())
			return
		}
		ca.mu.Lock()
		ca.renewals++
		ca.mu.Unlock()
		ca.issue(t, w, leaf.PublicKey, leaf.Subject, leaf.EmailAddresses)
	})
	ca.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ca.Server.Close)
	return ca
}

// Renewals counts the renewals it granted.
func (ca *CA) Renewals() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.renewals
}

// Refusals lists why it refused requests.
func (ca *CA) Refusals() []string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return append([]string(nil), ca.refusals...)
}

// Fingerprint is the SHA-256 of its TLS root, hex.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.Server.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

// Issue signs a device certificate for pub, as the authority would have at
// enrollment.
func (ca *CA) Issue(t testing.TB, pub crypto.PublicKey, cn, email string, notBefore, notAfter time.Time) *x509.Certificate {
	return ca.PKI.Device(t, pub, cn, email, notBefore, notAfter)
}

func (ca *CA) refuse(w http.ResponseWriter, status int, msg string) {
	ca.mu.Lock()
	ca.refusals = append(ca.refusals, msg)
	ca.mu.Unlock()
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": status, "message": msg})
}

func (ca *CA) issue(t testing.TB, w http.ResponseWriter, pub crypto.PublicKey, subject pkix.Name, emails []string) {
	leaf := ca.PKI.Device(t, pub, subject.CommonName, strings.Join(emails, ""), time.Now().Add(-time.Minute), time.Now().Add(ca.Life))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"crt":       PEM(leaf),
		"ca":        PEM(ca.PKI.Intermediate),
		"certChain": []string{PEM(leaf), PEM(ca.PKI.Intermediate)},
	})
}

// checkRenewToken does what step-ca's AuthorizeRenewToken does: the chain
// in x5cInsecure must reach the root for client authentication, whatever
// the leaf's validity; the leaf's key must have signed the token; sub is
// the leaf's common name, iss step's client, aud the renew URL, the times
// current within a minute, and the token is used once.
func (ca *CA) checkRenewToken(tok string, aud string, now time.Time) (*x509.Certificate, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	var h struct {
		Alg         string   `json:"alg"`
		X5CInsecure []string `json:"x5cInsecure"`
	}
	var c stepca.RenewClaims
	if err := decodePart(parts[0], &h); err != nil {
		return nil, err
	}
	if err := decodePart(parts[1], &c); err != nil {
		return nil, err
	}
	if len(h.X5CInsecure) == 0 {
		return nil, errors.New("missing x5cInsecure header")
	}
	var chain []*x509.Certificate
	for _, s := range h.X5CInsecure {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	leaf := chain[0]
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.PKI.Root)
	for _, x := range chain[1:] {
		inter.AddCert(x)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter,
		CurrentTime: leaf.NotAfter.Add(-time.Minute),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("the certificate cannot sign")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if h.Alg != "ES256" || len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("bad signature")
		}
	case *rsa.PublicKey:
		if h.Alg != "PS256" || rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil {
			return nil, errors.New("bad signature")
		}
	default:
		return nil, errors.New("unsupported key")
	}
	leeway := int64(60)
	switch n := now.Unix(); {
	case c.Iss != stepca.RenewIssuer:
		return nil, errors.New("invalid issuer claim (iss)")
	case c.Sub != leaf.Subject.CommonName:
		return nil, errors.New("invalid subject claim (sub)")
	case c.Aud != aud:
		return nil, errors.New("invalid audience claim (aud)")
	case c.Nbf > n+leeway:
		return nil, errors.New("token not valid yet (nbf)")
	case c.Exp < n-leeway:
		return nil, errors.New("token is expired (exp)")
	case c.Iat > n+leeway:
		return nil, errors.New("token issued in the future (iat)")
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.seen[tok] {
		return nil, errors.New("token already used")
	}
	ca.seen[tok] = true
	return leaf, nil
}

func decodePart(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// PEM encodes a certificate.
func PEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

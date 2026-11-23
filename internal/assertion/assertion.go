// Package assertion signs the short assertion every Tender request carries:
//
//	Authorization: Device <compact JWS>
//
// The protected header holds alg (ES256 or PS256, whichever the key is),
// typ tender+jwt, and x5c, the device certificate first, then any
// intermediates, never the root. The claims bind the assertion to one
// request: aud (the member's origin), htm, htu (the URL without its query),
// bh (base64url SHA-256 of the body), iat, exp (iat + 300 at most), and jti
// (16 random bytes).
package assertion

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Scheme is the Authorization header's scheme.
const Scheme = "Device"

// Type is the JWS typ.
const Type = "tender+jwt"

// Lifetime is how long an assertion lives.
const Lifetime = 300 * time.Second

// Key is what signs: the device's key, and its certificate chain with the
// leaf first.
type Key struct {
	Signer crypto.Signer
	Chain  []*x509.Certificate
}

// Header is the JWS protected header.
type Header struct {
	Alg string   `json:"alg"`
	Typ string   `json:"typ"`
	X5C []string `json:"x5c"`
}

// Claims are the JWS claims.
type Claims struct {
	Aud string `json:"aud"`
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Bh  string `json:"bh"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

var b64 = base64.RawURLEncoding

// Sign makes the compact JWS for one request.
func Sign(k Key, method string, u *url.URL, body []byte, now time.Time) (string, error) {
	alg, err := Algorithm(k.Signer.Public())
	if err != nil {
		return "", err
	}
	if len(k.Chain) == 0 {
		return "", errors.New("assertion: no certificate")
	}
	h := Header{Alg: alg, Typ: Type}
	for _, c := range WithoutRoot(k.Chain) {
		h.X5C = append(h.X5C, base64.StdEncoding.EncodeToString(c.Raw))
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	c := Claims{
		Aud: u.Scheme + "://" + u.Host,
		Htm: strings.ToUpper(method),
		Htu: TargetURI(u),
		Bh:  b64.EncodeToString(sum[:]),
		Iat: now.Unix(),
		Exp: now.Add(Lifetime).Unix(),
		Jti: b64.EncodeToString(jti),
	}
	hj, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	cj, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hj) + "." + b64.EncodeToString(cj)
	sig, err := sign(k.Signer, alg, []byte(input))
	if err != nil {
		return "", fmt.Errorf("assertion: sign: %w", err)
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// TargetURI is the request URL without its query or fragment.
func TargetURI(u *url.URL) string {
	t := *u
	t.RawQuery, t.ForceQuery, t.Fragment, t.RawFragment, t.User = "", false, "", "", nil
	return t.String()
}

// Algorithm names the JWS algorithm a public key signs with.
func Algorithm(pub crypto.PublicKey) (string, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return "", fmt.Errorf("assertion: an EC key must be P-256, not %s", p.Curve.Params().Name)
		}
		return "ES256", nil
	case *rsa.PublicKey:
		return "PS256", nil
	default:
		return "", fmt.Errorf("assertion: unsupported key type %T", pub)
	}
}

// WithoutRoot drops a self-signed certificate from the end of a chain.
func WithoutRoot(chain []*x509.Certificate) []*x509.Certificate {
	if n := len(chain); n > 1 {
		last := chain[n-1]
		if bytes.Equal(last.RawIssuer, last.RawSubject) && last.CheckSignatureFrom(last) == nil {
			return chain[:n-1]
		}
	}
	return chain
}

func sign(s crypto.Signer, alg string, input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	switch alg {
	case "ES256":
		der, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		var sig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &sig); err != nil {
			return nil, fmt.Errorf("decode ECDSA signature: %w", err)
		}
		out := make([]byte, 64)
		sig.R.FillBytes(out[:32])
		sig.S.FillBytes(out[32:])
		return out, nil
	default: // PS256
		return s.Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	}
}

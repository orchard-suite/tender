// Package identity finds the device's certificate and key, and makes a new
// key for enrollment. On macOS it uses the keychain, on Windows the
// certificate store (CurrentUser\My), and elsewhere a key file and a cert
// file. The key never leaves the store, and Tender never copies it.
package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/orchard-suite/tender/internal/assertion"
	"github.com/orchard-suite/tender/internal/config"
)

// Identity is a certificate chain, leaf first and never the root, and the
// key that signs for it.
type Identity struct {
	Signer crypto.Signer
	Chain  []*x509.Certificate
	Store  string // keychain, certstore, or file
}

// Key is the identity as the assertion signer takes it.
func (i *Identity) Key() assertion.Key { return assertion.Key{Signer: i.Signer, Chain: i.Chain} }

// Leaf is the device certificate.
func (i *Identity) Leaf() *x509.Certificate { return i.Chain[0] }

// ErrNotFound says no certificate matched.
var ErrNotFound = errors.New("no device certificate found")

// Load finds the identity the config names: key and cert files when it
// names them, else the store identity its issuer signed. On an operating
// system with no store, it reads the default key and cert files in the
// state directory.
func Load(cfg config.Identity, stateDir string, now time.Time) (*Identity, error) {
	if cfg.Files() {
		return loadFiles(config.ExpandHome(cfg.Key), config.ExpandHome(cfg.Cert), cfg.Issuer, now)
	}
	if !HasStore {
		key, cert := DefaultFiles(stateDir)
		return loadFiles(key, cert, cfg.Issuer, now)
	}
	if cfg.Issuer == "" {
		return nil, errors.New("tender.yaml names no identity: set identity.issuer to the issuer of the device certificate")
	}
	return loadStore(cfg.Issuer, now)
}

// DefaultFiles are where an enrolled key and cert live on an operating
// system with no store.
func DefaultFiles(stateDir string) (key, cert string) {
	return filepath.Join(stateDir, "device.key"), filepath.Join(stateDir, "device.crt")
}

// Candidates filters certificates to the ones that can be the device's:
// issued by issuer, for client authentication, and valid now. The newest
// comes first.
func Candidates(certs []*x509.Certificate, issuer string, now time.Time) []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range certs {
		if issuer != "" && !IssuerMatches(c, issuer) {
			continue
		}
		if !clientAuth(c) || now.Before(c.NotBefore) || now.After(c.NotAfter) {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].NotBefore.After(out[j].NotBefore) })
	return out
}

func clientAuth(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

var shortNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.17":                   "POSTALCODE",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "E",
}

// IssuerMatches reports whether a certificate's issuer holds every
// attribute of want, a distinguished name such as
// "CN=Example Devices Issuing CA, O=Example". Order and case do not
// matter. A want with no "=" is a common name.
func IssuerMatches(c *x509.Certificate, want string) bool {
	have := map[string]bool{}
	for _, atv := range c.Issuer.Names {
		name, ok := shortNames[atv.Type.String()]
		if !ok {
			name = atv.Type.String()
		}
		have[pair(name, fmt.Sprint(atv.Value))] = true
	}
	pairs := splitDN(want)
	if len(pairs) == 0 {
		return false
	}
	for _, p := range pairs {
		if !have[p] {
			return false
		}
	}
	return true
}

func pair(k, v string) string {
	k = strings.ToUpper(strings.TrimSpace(k))
	if k == "EMAILADDRESS" {
		k = "E"
	}
	return k + "=" + strings.ToLower(strings.TrimSpace(v))
}

// splitDN splits "CN=a\, b, O=c" into normalized pairs. Commas and
// semicolons separate; a backslash escapes.
func splitDN(dn string) []string {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil
	}
	if !strings.Contains(dn, "=") {
		return []string{pair("CN", dn)}
	}
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(dn); i++ {
		switch ch := dn[i]; {
		case ch == '\\' && i+1 < len(dn):
			i++
			cur.WriteByte(dn[i])
		case ch == ',' || ch == ';':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	parts = append(parts, cur.String())
	var out []string
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if ok {
			out = append(out, pair(k, v))
		}
	}
	return out
}

// BuildChain puts a leaf's issuers after it from pool, stopping at a
// self-signed certificate, which it leaves out.
func BuildChain(leaf *x509.Certificate, pool []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	cur := leaf
	for range 8 {
		if selfSigned(cur) {
			break
		}
		var parent *x509.Certificate
		for _, p := range pool {
			if bytes.Equal(p.RawSubject, cur.RawIssuer) && cur.CheckSignatureFrom(p) == nil {
				parent = p
				break
			}
		}
		if parent == nil || selfSigned(parent) {
			break
		}
		chain = append(chain, parent)
		cur = parent
	}
	return chain
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// PublicKeyID is the SHA-256 of a public key's SubjectPublicKeyInfo, in
// hex. It ties a certificate to the key Tender made at enrollment.
func PublicKeyID(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// keychainHash is the keychain's kSecAttrApplicationLabel for a public
// key: the SHA-1 of the uncompressed EC point, or of the PKCS #1 RSA key.
func keychainHash(pub crypto.PublicKey) ([]byte, error) {
	var b []byte
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		k, err := p.ECDH()
		if err != nil {
			return nil, err
		}
		b = k.Bytes()
	case *rsa.PublicKey:
		b = x509.MarshalPKCS1PublicKey(p)
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}
	sum := sha1.Sum(b) //nolint:gosec // the keychain names keys by SHA-1
	return sum[:], nil
}

// CSR builds a certificate signing request naming the device (CN) and its
// person (one SAN email).
func CSR(signer crypto.Signer, device, email string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: device},
	}
	if email != "" {
		tmpl.EmailAddresses = []string{email}
	}
	if _, ok := signer.Public().(*rsa.PublicKey); ok {
		tmpl.SignatureAlgorithm = x509.SHA256WithRSAPSS
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
}

// samePublicKey compares two public keys.
func samePublicKey(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

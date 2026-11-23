// Package stepca enrolls a device with a smallstep step-ca authority and
// renews what it enrolled. It is all Tender knows of a certificate
// authority: an estate on another authority gets a package beside it.
//
// Enrollment: the person signs in through the browser to the authority's
// OIDC provisioner (the authorization code flow with PKCE, on a loopback
// redirect), and Tender hands the ID token to /1.0/sign as the one-time
// token beside its signing request. Renewal: /1.0/renew, with a token the
// current certificate's key signs as the bearer, so it passes a proxy that
// ends TLS in front of the authority.
package stepca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/orchard-suite/tender/internal/assertion"
)

// Authority is this package's name in an enrollment record.
const Authority = "step-ca"

// Record is what Tender keeps after it enrolls, so it can renew what it
// enrolled and nothing else.
type Record struct {
	Authority   string    `json:"authority"`
	CA          string    `json:"ca"`
	Root        string    `json:"root,omitempty"` // PEM, when the authority's TLS is under its own root
	Provisioner string    `json:"provisioner"`
	Store       string    `json:"store"`
	Key         string    `json:"key"`        // the store's name for the key
	PublicKey   string    `json:"public_key"` // SHA-256 of the key's SubjectPublicKeyInfo, hex
	Enrolled    time.Time `json:"enrolled"`
	Renewed     time.Time `json:"renewed,omitzero"`
}

// Client talks to one authority.
type Client struct {
	URL  *url.URL
	Root *x509.Certificate // nil when the system's roots verify the authority
	HTTP *http.Client
}

// New makes a client. With a fingerprint (the SHA-256 of the authority's
// root, hex), it fetches the root and checks it, as step ca bootstrap
// does; without one, the system's roots must verify the authority. A root
// already held (PEM) is used as it is.
func New(ctx context.Context, caURL, fingerprint, rootPEM string) (*Client, error) {
	u, err := url.Parse(caURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the authority's address %q must be https", caURL)
	}
	c := &Client{URL: u}
	switch {
	case rootPEM != "":
		block, _ := pem.Decode([]byte(rootPEM))
		if block == nil {
			return nil, errors.New("the saved root is not PEM")
		}
		if c.Root, err = x509.ParseCertificate(block.Bytes); err != nil {
			return nil, err
		}
	case fingerprint != "":
		if c.Root, err = fetchRoot(ctx, u, fingerprint); err != nil {
			return nil, err
		}
	}
	c.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: c.transport()}
	return c, nil
}

// RootPEM is the authority's root as PEM, or empty.
func (c *Client) RootPEM() string {
	if c.Root == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Root.Raw}))
}

func (c *Client) transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.Root != nil {
		pool := x509.NewCertPool()
		pool.AddCert(c.Root)
		t.TLSClientConfig.RootCAs = pool
	}
	return t
}

func fetchRoot(ctx context.Context, u *url.URL, fingerprint string) (*x509.Certificate, error) {
	fp := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	t := http.DefaultTransport.(*http.Transport).Clone()
	// The fingerprint, not the TLS chain, proves the root: it is checked below.
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // checked by fingerprint
	hc := &http.Client{Timeout: 30 * time.Second, Transport: t}
	var resp struct {
		CA string `json:"ca"`
	}
	if err := call(ctx, hc, http.MethodGet, u.JoinPath("root", fp).String(), nil, &resp); err != nil {
		return nil, fmt.Errorf("fetch the authority's root: %w", err)
	}
	block, _ := pem.Decode([]byte(resp.CA))
	if block == nil {
		return nil, errors.New("the authority's root is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != fp {
		return nil, errors.New("the authority's root does not match the fingerprint")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Provisioner is the part of a step-ca provisioner Tender reads.
type Provisioner struct {
	Type                  string `json:"type"`
	Name                  string `json:"name"`
	ClientID              string `json:"clientID"`
	ClientSecret          string `json:"clientSecret"`
	ConfigurationEndpoint string `json:"configurationEndpoint"`
	ListenAddress         string `json:"listenAddress"`
}

// OIDCProvisioner picks the OIDC provisioner by name, or the only one.
func (c *Client) OIDCProvisioner(ctx context.Context, name string) (Provisioner, error) {
	var found []Provisioner
	cursor := ""
	for range 20 {
		u := c.URL.JoinPath("provisioners")
		if cursor != "" {
			u.RawQuery = url.Values{"cursor": {cursor}}.Encode()
		}
		var page struct {
			Provisioners []Provisioner `json:"provisioners"`
			NextCursor   string        `json:"nextCursor"`
		}
		if err := call(ctx, c.HTTP, http.MethodGet, u.String(), nil, &page); err != nil {
			return Provisioner{}, fmt.Errorf("list provisioners: %w", err)
		}
		for _, p := range page.Provisioners {
			if strings.EqualFold(p.Type, "OIDC") && (name == "" || p.Name == name) {
				found = append(found, p)
			}
		}
		if page.NextCursor == "" || len(page.Provisioners) == 0 {
			break
		}
		cursor = page.NextCursor
	}
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) == 0 && name != "":
		return Provisioner{}, fmt.Errorf("the authority has no OIDC provisioner named %q", name)
	case len(found) == 0:
		return Provisioner{}, errors.New("the authority has no OIDC provisioner")
	default:
		names := make([]string, len(found))
		for i, p := range found {
			names[i] = p.Name
		}
		return Provisioner{}, fmt.Errorf("the authority has several OIDC provisioners (%s); name one with --provisioner", strings.Join(names, ", "))
	}
}

type signResponse struct {
	Crt       string   `json:"crt"`
	CA        string   `json:"ca"`
	CertChain []string `json:"certChain"`
}

func (r signResponse) chain() ([]*x509.Certificate, error) {
	pems := r.CertChain
	if len(pems) == 0 {
		pems = []string{r.Crt, r.CA}
	}
	var out []*x509.Certificate
	for _, p := range pems {
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("the authority returned no certificate")
	}
	return out, nil
}

// Sign hands the authority a signing request (DER) and the sign-in's ID
// token, and returns the chain it signed, leaf first.
func (c *Client) Sign(ctx context.Context, csrDER []byte, ott string) ([]*x509.Certificate, error) {
	body := map[string]string{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ott": ott,
	}
	var resp signResponse
	if err := call(ctx, c.HTTP, http.MethodPost, c.URL.JoinPath("1.0", "sign").String(), body, &resp); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return resp.chain()
}

// RenewIssuer is the iss of a renewal token, as step's own client sends it.
const RenewIssuer = "step-ca-client/1.0"

// RenewTokenLifetime is how long a renewal token lives.
const RenewTokenLifetime = 5 * time.Minute

// renewHeader is a renewal token's header. step-ca reads the chain from
// x5cInsecure, which it verifies against its roots without checking
// validity, so an expired certificate can still prove its key.
type renewHeader struct {
	Alg         string   `json:"alg"`
	Typ         string   `json:"typ"`
	X5CInsecure []string `json:"x5cInsecure"`
}

// RenewClaims are a renewal token's claims.
type RenewClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"` // the certificate's common name
	Aud string `json:"aud"` // the renew URL
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

// Renew asks the authority for a new certificate for the same key. It
// proves the current certificate with a token signed by its key, sent as
// Authorization: Bearer, not with TLS client authentication, so it passes
// a proxy that ends TLS in front of the authority.
func (c *Client) Renew(ctx context.Context, chain []*x509.Certificate, key crypto.Signer) ([]*x509.Certificate, error) {
	renewURL := c.URL.JoinPath("1.0", "renew").String()
	tok, err := renewToken(key, chain, renewURL, time.Now())
	if err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	var resp signResponse
	if err := callAuth(ctx, c.HTTP, http.MethodPost, renewURL, "Bearer "+tok, nil, &resp); err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	return resp.chain()
}

func renewToken(key crypto.Signer, chain []*x509.Certificate, aud string, now time.Time) (string, error) {
	alg, err := assertion.Algorithm(key.Public())
	if err != nil {
		return "", err
	}
	h := renewHeader{Alg: alg, Typ: "JWT"}
	for _, x := range assertion.WithoutRoot(chain) {
		h.X5CInsecure = append(h.X5CInsecure, base64.StdEncoding.EncodeToString(x.Raw))
	}
	jti, err := assertion.NewID()
	if err != nil {
		return "", err
	}
	claims := RenewClaims{
		Iss: RenewIssuer,
		Sub: chain[0].Subject.CommonName,
		Aud: aud,
		Iat: now.Unix(),
		Nbf: now.Unix(),
		Exp: now.Add(RenewTokenLifetime).Unix(),
		Jti: jti,
	}
	return assertion.Compact(key, alg, h, claims)
}

// DueForRenewal reports whether less than a third of a certificate's life
// is left.
func DueForRenewal(leaf *x509.Certificate, now time.Time) bool {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Sub(now) < life/3
}

func call(ctx context.Context, hc *http.Client, method, u string, in, out any) error {
	return callAuth(ctx, hc, method, u, "", in, out)
}

func callAuth(ctx context.Context, hc *http.Client, method, u, authorization string, in, out any) error {
	var body io.Reader = http.NoBody
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			return fmt.Errorf("%d: %s", resp.StatusCode, e.Message)
		}
		return fmt.Errorf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return json.Unmarshal(b, out)
}

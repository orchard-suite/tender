// Package stepca enrolls a device with a smallstep step-ca authority and
// renews what it enrolled. It is all Tender knows of a certificate
// authority: an estate on another authority gets a package beside it.
//
// Enrollment: the person signs in through the browser to the authority's
// OIDC provisioner (the authorization code flow with PKCE, on a loopback
// redirect), and Tender hands the ID token to /1.0/sign as the one-time
// token beside its signing request. Renewal: /1.0/renew, with the current
// certificate as the TLS client certificate.
package stepca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	c.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: c.transport(nil)}
	return c, nil
}

// RootPEM is the authority's root as PEM, or empty.
func (c *Client) RootPEM() string {
	if c.Root == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Root.Raw}))
}

func (c *Client) transport(cert *tls.Certificate) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.Root != nil {
		pool := x509.NewCertPool()
		pool.AddCert(c.Root)
		t.TLSClientConfig.RootCAs = pool
	}
	if cert != nil {
		t.TLSClientConfig.Certificates = []tls.Certificate{*cert}
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

// Renew asks the authority for a new certificate for the same key, proving
// the current one with TLS client authentication.
func (c *Client) Renew(ctx context.Context, chain []*x509.Certificate, key crypto.Signer) ([]*x509.Certificate, error) {
	cert := &tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, x := range chain {
		cert.Certificate = append(cert.Certificate, x.Raw)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: c.transport(cert)}
	var resp signResponse
	if err := call(ctx, hc, http.MethodPost, c.URL.JoinPath("1.0", "renew").String(), nil, &resp); err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	return resp.chain()
}

// DueForRenewal reports whether less than a third of a certificate's life
// is left.
func DueForRenewal(leaf *x509.Certificate, now time.Time) bool {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Sub(now) < life/3
}

func call(ctx context.Context, hc *http.Client, method, u string, in, out any) error {
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

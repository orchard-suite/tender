package stepca

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SignIn is the ID token a sign-in gave, and the email in it.
type SignIn struct {
	IDToken string
	Email   string
}

// Browser opens a URL for the person.
type Browser func(url string) error

// SignInOIDC runs the authorization code flow with PKCE against the
// provisioner's identity provider, receiving the code on a loopback
// redirect, and returns the ID token. It never sees the person's password.
func (c *Client) SignInOIDC(ctx context.Context, p Provisioner, open Browser) (SignIn, error) {
	var disc struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	if err := call(ctx, hc, http.MethodGet, p.ConfigurationEndpoint, nil, &disc); err != nil {
		return SignIn{}, fmt.Errorf("read the identity provider's configuration: %w", err)
	}
	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" {
		return SignIn{}, errors.New("the identity provider's configuration names no authorization or token endpoint")
	}

	ln, err := net.Listen("tcp", loopbackAddress(p.ListenAddress))
	if err != nil {
		return SignIn{}, fmt.Errorf("listen for the sign-in: %w", err)
	}
	defer ln.Close()
	redirect := "http://" + ln.Addr().String()

	verifier, stateTok, nonce := random(32), random(16), random(16)
	challenge := sha256.Sum256([]byte(verifier))
	auth, err := url.Parse(disc.AuthorizationEndpoint)
	if err != nil {
		return SignIn{}, err
	}
	q := auth.Query()
	for k, v := range map[string]string{
		"client_id":             p.ClientID,
		"response_type":         "code",
		"scope":                 "openid email",
		"redirect_uri":          redirect,
		"state":                 stateTok,
		"nonce":                 nonce,
		"code_challenge":        base64.RawURLEncoding.EncodeToString(challenge[:]),
		"code_challenge_method": "S256",
	} {
		q.Set(k, v)
	}
	auth.RawQuery = q.Encode()

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		if v.Get("code") == "" && v.Get("error") == "" {
			http.NotFound(w, r)
			return
		}
		var res result
		switch {
		case v.Get("error") != "":
			res.err = fmt.Errorf("the sign-in failed: %s %s", v.Get("error"), v.Get("error_description"))
		case v.Get("state") != stateTok:
			res.err = errors.New("the sign-in came back with the wrong state")
		default:
			res.code = v.Get("code")
		}
		msg := "Signed in. You can close this window."
		if res.err != nil {
			msg = res.err.Error()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>Tender</title><p>%s</p>", html.EscapeString(msg))
		select {
		case done <- res:
		default:
		}
	})}
	go srv.Serve(ln) //nolint:errcheck // closed below
	defer srv.Close()

	if err := open(auth.String()); err != nil {
		return SignIn{}, err
	}
	var res result
	select {
	case res = <-done:
	case <-ctx.Done():
		return SignIn{}, ctx.Err()
	}
	if res.err != nil {
		return SignIn{}, res.err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {res.code},
		"redirect_uri":  {redirect},
		"client_id":     {p.ClientID},
		"code_verifier": {verifier},
	}
	if p.ClientSecret != "" {
		form.Set("client_secret", p.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return SignIn{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return SignIn{}, fmt.Errorf("redeem the sign-in: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return SignIn{}, fmt.Errorf("redeem the sign-in: %d %w", resp.StatusCode, err)
	}
	if tok.IDToken == "" {
		return SignIn{}, fmt.Errorf("redeem the sign-in: %d %s %s", resp.StatusCode, tok.Error, tok.Desc)
	}
	claims, err := unverifiedClaims(tok.IDToken)
	if err != nil {
		return SignIn{}, err
	}
	// The authority checks the token's signature; this checks it answers
	// this sign-in.
	if claims.Nonce != nonce {
		return SignIn{}, errors.New("the ID token does not answer this sign-in")
	}
	return SignIn{IDToken: tok.IDToken, Email: claims.Email}, nil
}

type idClaims struct {
	Email string `json:"email"`
	Nonce string `json:"nonce"`
}

func unverifiedClaims(tok string) (idClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return idClaims{}, errors.New("the ID token is not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idClaims{}, fmt.Errorf("the ID token: %w", err)
	}
	var c idClaims
	if err := json.Unmarshal(b, &c); err != nil {
		return idClaims{}, fmt.Errorf("the ID token: %w", err)
	}
	return c, nil
}

// loopbackAddress is where the redirect lands: the provisioner's listen
// address when it names one (its port is registered with the identity
// provider), else any free port, always on 127.0.0.1.
func loopbackAddress(listen string) string {
	if listen == "" {
		return "127.0.0.1:0"
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1:0"
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

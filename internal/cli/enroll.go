package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/identity"
	"github.com/orchard-suite/tender/internal/state"
	"github.com/orchard-suite/tender/internal/stepca"
)

const enrollmentFile = "enrollment.json"

func (e *env) enrollmentPath() string { return filepath.Join(e.paths.State, enrollmentFile) }

func (e *env) loadEnrollment() (*stepca.Record, error) {
	b, err := os.ReadFile(e.enrollmentPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r stepca.Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", e.enrollmentPath(), err)
	}
	return &r, nil
}

func (e *env) saveEnrollment(r *stepca.Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteFile(e.enrollmentPath(), append(b, '\n'))
}

func cmdEnroll(ctx context.Context, e *env, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	ca := fs.String("ca", "", "the estate's step-ca address, such as https://ca.example.com")
	fingerprint := fs.String("fingerprint", "", "the SHA-256 of the authority's root, when its TLS is under its own root")
	provisioner := fs.String("provisioner", "", "the OIDC provisioner to sign in with, when the authority has several")
	email := fs.String("email", "", "the person the certificate names; default: the email the sign-in gives")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ca == "" {
		return errors.New("enroll needs --ca <url>")
	}
	cfg, err := e.loadConfig()
	if err != nil {
		return err
	}
	client, err := stepca.New(ctx, *ca, *fingerprint, "")
	if err != nil {
		return err
	}
	prov, err := client.OIDCProvisioner(ctx, *provisioner)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "Signing in with %s. Your browser opens; if it does not, open the address below.\n", prov.Name)
	signIn, err := client.SignInOIDC(ctx, prov, func(u string) error {
		fmt.Fprintln(e.out, u)
		openBrowser(u)
		return nil
	})
	if err != nil {
		return err
	}
	person := *email
	if person == "" {
		person = signIn.Email
	}
	if person == "" {
		return errors.New("the sign-in gave no email; name the person with --email")
	}

	store, err := identity.StoreFor(cfg.Identity, e.paths.State)
	if err != nil {
		return err
	}
	ref, signer, err := store.CreateKey()
	if err != nil {
		return fmt.Errorf("make the key in the %s: %w", store.Name(), err)
	}
	csr, err := identity.CSR(signer, deviceName(), person)
	if err != nil {
		return err
	}
	chain, err := client.Sign(ctx, csr, signIn.IDToken)
	if err != nil {
		return err
	}
	if identity.PublicKeyID(chain[0].PublicKey) != identity.PublicKeyID(signer.Public()) {
		return errors.New("the authority signed a certificate for another key")
	}
	if err := store.Install(ref, chain); err != nil {
		return fmt.Errorf("keep the certificate in the %s: %w", store.Name(), err)
	}
	rec := &stepca.Record{
		Authority:   stepca.Authority,
		CA:          *ca,
		Root:        client.RootPEM(),
		Provisioner: prov.Name,
		Store:       store.Name(),
		Key:         ref,
		PublicKey:   identity.PublicKeyID(signer.Public()),
		Enrolled:    e.now().UTC(),
	}
	if err := e.saveEnrollment(rec); err != nil {
		return err
	}
	leaf := chain[0]
	e.log.Info("enrolled", "authority", *ca, "store", store.Name(), "issuer", leaf.Issuer.String(), "not_after", leaf.NotAfter)
	fmt.Fprintf(e.out, "Enrolled %s for %s, in the %s.\nIssuer:  %s\nExpires: %s\n",
		leaf.Subject.CommonName, person, store.Name(), leaf.Issuer.String(), localTime(leaf.NotAfter))
	if !cfg.Identity.Files() && (cfg.Identity.Issuer == "" || !identity.IssuerMatches(leaf, cfg.Identity.Issuer)) && identity.HasStore {
		fmt.Fprintf(e.out, "\ntender.yaml must pick this certificate. Set:\n\nidentity:\n  issuer: %q\n", leaf.Issuer.String())
	}
	return nil
}

func cmdRenew(ctx context.Context, e *env, args []string) error {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	force := fs.Bool("force", false, "renew now, however much of its life is left")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := e.loadConfig()
	if err != nil {
		return err
	}
	keys := &keyring{cfg: cfg.Identity, stateDir: e.paths.State, now: e.now}
	renewed, err := e.renew(ctx, cfg, keys, *force)
	if err != nil {
		return err
	}
	if !renewed {
		fmt.Fprintln(e.out, "Not due: more than a third of its life is left. Use --force to renew now.")
		return nil
	}
	keys.forget()
	id, err := keys.Identity()
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "Renewed. Expires: %s\n", localTime(id.Leaf().NotAfter))
	return nil
}

// errManaged says the certificate is device management's to renew.
var errManaged = errors.New("this certificate was not enrolled by Tender; device management renews it")

// renew renews the certificate Tender enrolled when less than a third of
// its life is left, or now with force. A certificate device management
// issued is never renewed here.
func (e *env) renew(ctx context.Context, cfg *config.Config, keys *keyring, force bool) (bool, error) {
	rec, err := e.loadEnrollment()
	if err != nil {
		return false, err
	}
	id, err := keys.Identity()
	if err != nil {
		if rec == nil {
			return false, nil // nothing enrolled and nothing found: nothing to renew
		}
		return false, err
	}
	leaf := id.Leaf()
	if rec == nil || rec.PublicKey != identity.PublicKeyID(leaf.PublicKey) {
		if force {
			return false, errManaged
		}
		return false, nil
	}
	if !force && !stepca.DueForRenewal(leaf, e.now()) {
		return false, nil
	}
	if rec.Authority != stepca.Authority {
		return false, fmt.Errorf("enrolled with %q, an authority this build does not know", rec.Authority)
	}
	client, err := stepca.New(ctx, rec.CA, "", rec.Root)
	if err != nil {
		return false, err
	}
	chain, err := client.Renew(ctx, id.Chain, id.Signer)
	if err != nil {
		return false, err
	}
	if identity.PublicKeyID(chain[0].PublicKey) != rec.PublicKey {
		return false, errors.New("the authority renewed for another key")
	}
	store, err := identity.StoreFor(cfg.Identity, e.paths.State)
	if err != nil {
		return false, err
	}
	if err := store.Install(rec.Key, chain); err != nil {
		return false, err
	}
	if chain[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		if err := store.Remove(leaf); err != nil {
			e.log.Warn("old certificate not removed", "serial", leaf.SerialNumber.String(), "error", err.Error())
		}
	}
	rec.Renewed = e.now().UTC()
	if err := e.saveEnrollment(rec); err != nil {
		return false, err
	}
	e.log.Info("renewed", "authority", rec.CA, "not_after", chain[0].NotAfter)
	return true, nil
}

// deviceName is the machine's host name, without its domain.
func deviceName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	h, _, _ = strings.Cut(h, ".")
	return strings.ToLower(h)
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}

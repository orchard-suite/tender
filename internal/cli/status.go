package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/orchard-suite/tender/internal/identity"
	"github.com/orchard-suite/tender/internal/state"
)

func cmdStatus(_ context.Context, e *env, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := e.loadConfig()
	if err != nil {
		return err
	}
	st, err := state.Load(e.statePath())
	if err != nil {
		return err
	}
	w := e.out
	fmt.Fprintf(w, "Tender %s\n\nIdentity\n", Version)
	id, err := identity.Load(cfg.Identity, e.paths.State, e.now())
	if err != nil {
		fmt.Fprintf(w, "  none: %v\n", err)
	} else {
		leaf := id.Leaf()
		person := ""
		if len(leaf.EmailAddresses) > 0 {
			person = leaf.EmailAddresses[0]
		}
		fmt.Fprintf(w, "  store    %s\n  issuer   %s\n  subject  %s\n", id.Store, leaf.Issuer.String(), leaf.Subject.String())
		if person != "" {
			fmt.Fprintf(w, "  person   %s\n", person)
		}
		fmt.Fprintf(w, "  expires  %s (%s)\n", localTime(leaf.NotAfter), until(leaf.NotAfter.Sub(e.now())))
		fmt.Fprintf(w, "  chain    %d certificate(s), root left out\n", len(id.Chain))
		rec, _ := e.loadEnrollment()
		if rec != nil && rec.PublicKey == identity.PublicKeyID(leaf.PublicKey) {
			fmt.Fprintf(w, "  renewal  Tender renews it with %s when a third of its life is left\n", rec.CA)
		} else {
			fmt.Fprintf(w, "  renewal  device management renews it\n")
		}
	}

	fmt.Fprintf(w, "\nReaders\n")
	names := map[string]bool{}
	for n := range Readers {
		names[n] = true
	}
	for n := range cfg.Readers {
		names[n] = true
	}
	for _, name := range sortedNames(names) {
		r, inConfig := cfg.Readers[name]
		_, built := Readers[name]
		switch {
		case !built:
			fmt.Fprintf(w, "  %-8s not in this build\n", name)
			continue
		case !inConfig || r.Address == "":
			fmt.Fprintf(w, "  %-8s off: no address\n", name)
			continue
		}
		fmt.Fprintf(w, "  %-8s %s\n", name, r.Address)
		rs := st.Readers[name]
		if rs == nil {
			fmt.Fprintf(w, "           not run yet\n")
			continue
		}
		if a := rs.Answer; a != nil {
			if a.Accept {
				fmt.Fprintf(w, "           takes version %d every %s\n", a.Version, orDefault(a.Every, "15m"))
			} else {
				fmt.Fprintf(w, "           declines; asks again after %s\n", orDefault(a.Retry, "6h"))
			}
		}
		if rs.Last != nil {
			fmt.Fprintf(w, "           last     %s, %s\n", localTime(rs.Last.At), describe(*rs.Last))
		}
		if !rs.LastOK.IsZero() {
			fmt.Fprintf(w, "           last ok  %s\n", localTime(rs.LastOK))
		}
		if !rs.NextDue.IsZero() {
			fmt.Fprintf(w, "           next     %s\n", localTime(rs.NextDue))
		}
	}
	fmt.Fprintf(w, "\nConfig %s\nLogs   %s\n", e.paths.Config, e.paths.Logs)
	return nil
}

func localTime(t time.Time) string { return t.Local().Format("2006-01-02 15:04 MST") }

func until(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	days := int(d.Hours() / 24)
	if days >= 1 {
		return fmt.Sprintf("in %d days", days)
	}
	return "in " + strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

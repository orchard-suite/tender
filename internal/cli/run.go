package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/orchard-suite/tender/internal/agent"
	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/reader"
	"github.com/orchard-suite/tender/internal/service"
	"github.com/orchard-suite/tender/internal/state"
)

const (
	// maxSleep bounds a wait, so a changed config takes effect within it.
	maxSleep = 5 * time.Minute
	// renewEvery is how often the loop checks whether its certificate is due.
	renewEvery = time.Hour
)

func cmdRun(ctx context.Context, e *env, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := state.Load(e.statePath())
	if err != nil {
		return fmt.Errorf("read the state: %w", err)
	}
	cfg, stamp, err := e.loadConfigStamp()
	if err != nil {
		return err
	}
	keys := &keyring{cfg: cfg.Identity, stateDir: e.paths.State, now: e.now}
	a := e.newAgent(cfg, st, keys)
	e.log.Info("tender started", "readers", len(a.Endpoints), "config", e.paths.Config)
	var lastRenewCheck time.Time
	for {
		if c, s, err := e.loadConfigStamp(); err != nil {
			e.log.Warn("config not reloaded", "error", err.Error())
		} else if !s.Equal(stamp) {
			cfg, stamp = c, s
			keys = &keyring{cfg: cfg.Identity, stateDir: e.paths.State, now: e.now}
			a.Endpoints, a.Key = e.endpoints(cfg), keys.Key
			e.log.Info("config reloaded", "readers", len(a.Endpoints))
		}
		if e.now().Sub(lastRenewCheck) >= renewEvery {
			lastRenewCheck = e.now()
			if renewed, err := e.renew(ctx, cfg, keys, false); err != nil {
				e.log.Warn("renewal failed", "error", err.Error())
			} else if renewed {
				keys.forget()
			}
		}
		next := a.Tick(ctx)
		if err := state.Save(e.statePath(), st); err != nil {
			e.log.Warn("state not saved", "error", err.Error())
		}
		wait := maxSleep
		if !next.IsZero() {
			wait = min(max(next.Sub(e.now()), time.Second), maxSleep)
		}
		select {
		case <-ctx.Done():
			e.log.Info("tender stopped")
			return nil
		case <-time.After(wait):
		}
	}
}

// loadConfigStamp reads the config and the time it last changed.
func (e *env) loadConfigStamp() (*config.Config, time.Time, error) {
	var stamp time.Time
	if fi, err := os.Stat(e.paths.Config); err == nil {
		stamp = fi.ModTime()
	}
	c, err := e.loadConfig()
	return c, stamp, err
}

func cmdOnce(ctx context.Context, e *env, args []string) error {
	fs := flag.NewFlagSet("once", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := e.loadConfig()
	if err != nil {
		return err
	}
	st, err := state.Load(e.statePath())
	if err != nil {
		return fmt.Errorf("read the state: %w", err)
	}
	keys := &keyring{cfg: cfg.Identity, stateDir: e.paths.State, now: e.now}
	a := e.newAgent(cfg, st, keys)
	if len(a.Endpoints) == 0 {
		fmt.Fprintln(e.out, "No reader has an address; nothing to send.")
		return nil
	}
	results := a.Once(ctx)
	if err := state.Save(e.statePath(), st); err != nil {
		return fmt.Errorf("save the state: %w", err)
	}
	failed := false
	for _, name := range sortedNames(results) {
		fmt.Fprintf(e.out, "%-8s %s\n", name, describe(results[name]))
		if r := results[name]; r.Outcome != agent.Sent && r.Outcome != agent.Declined {
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("not every reader sent")
	}
	return nil
}

// describe prints a result as names and counts.
func describe(r state.Result) string {
	s := r.Outcome
	if r.Version != 0 {
		s += fmt.Sprintf(" v%d", r.Version)
	}
	if r.Bytes != 0 {
		s += fmt.Sprintf(", %d bytes", r.Bytes)
	}
	if len(r.Counts) > 0 {
		s += ", " + reader.FormatCounts(r.Counts)
	}
	if r.Status != 0 && r.Outcome != agent.Sent {
		s += fmt.Sprintf(", status %d", r.Status)
	}
	if r.Error != "" {
		s += ": " + r.Error
	}
	return s
}

func cmdInstall(_ context.Context, e *env, args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	where, err := service.Install(service.Spec{Exe: exe, LogDir: e.paths.Logs})
	if err != nil {
		return err
	}
	e.log.Info("service installed", "where", where)
	fmt.Fprintf(e.out, "Tender runs as this user's service: %s\nLogs: %s\n", where, e.paths.Logs)
	return nil
}

func cmdUninstall(_ context.Context, e *env, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	where, err := service.Uninstall()
	if err != nil {
		return err
	}
	e.log.Info("service removed", "where", where)
	fmt.Fprintf(e.out, "Removed %s\n", where)
	return nil
}

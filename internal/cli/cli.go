// Package cli is Tender's commands.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/orchard-suite/tender/internal/agent"
	"github.com/orchard-suite/tender/internal/assertion"
	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/identity"
	"github.com/orchard-suite/tender/internal/logfile"
	"github.com/orchard-suite/tender/internal/reader"
	"github.com/orchard-suite/tender/internal/readers/muster"
	"github.com/orchard-suite/tender/internal/state"
)

// Version is set at build time.
var Version = "dev"

// Readers are the readers this build carries, by name.
var Readers = map[string]reader.Reader{
	muster.Reader{}.Name(): muster.Reader{},
}

const usage = `Tender is the device agent. It reports names and counts from this machine to
the members an estate names, and takes no commands.

Usage:
  tender run         ask, read, and send for every reader, on the members' schedules
  tender once        ask, read, and send for every reader now, and print what it sent
  tender status      print the identity, the readers, and how each last went
  tender enroll --ca <url> [--fingerprint <sha256>] [--provisioner <name>] [--email <address>]
                     sign in and get a device certificate from the estate's authority
  tender renew [--force]
                     renew the certificate Tender enrolled
  tender install     run Tender as this user's service: at sign-in, always
  tender uninstall   remove the service
  tender version     print the version

Files:
  config   %s
  state    %s
  logs     %s
`

// Main runs a command and returns the exit code.
func Main(args []string) int {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tender:", err)
		return 1
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Printf(usage, paths.Config, paths.State, paths.Logs)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd, rest := args[0], args[1:]
	var run func(context.Context, *env, []string) error
	switch cmd {
	case "run":
		run = cmdRun
	case "once":
		run = cmdOnce
	case "status":
		run = cmdStatus
	case "enroll":
		run = cmdEnroll
	case "renew":
		run = cmdRenew
	case "install":
		run = cmdInstall
	case "uninstall":
		run = cmdUninstall
	case "version":
		fmt.Println("tender", Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "tender: unknown command %q\n", cmd)
		return 2
	}
	e, err := newEnv(paths, cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tender:", err)
		return 1
	}
	defer e.close()
	if err := run(ctx, e, rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		e.log.Error("command failed", "command", cmd, "error", err.Error())
		fmt.Fprintln(os.Stderr, "tender:", err)
		return 1
	}
	return 0
}

// env is what every command shares.
type env struct {
	paths config.Paths
	log   *slog.Logger
	out   io.Writer
	file  *logfile.Writer
	now   func() time.Time
}

func newEnv(paths config.Paths, cmd string) (*env, error) {
	w, err := logfile.Open(paths.Logs)
	if err != nil {
		return nil, fmt.Errorf("open the log: %w", err)
	}
	return &env{paths: paths, log: newLogger(w, cmd), out: os.Stdout, file: w, now: time.Now}, nil
}

// newLogger writes one JSON object per line, its time under `timestamp`.
func newLogger(w io.Writer, cmd string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Key = "timestamp"
			}
			return a
		},
	})
	return slog.New(h).With("command", cmd, "version", Version)
}

func (e *env) close() { e.file.Close() }

func (e *env) statePath() string { return filepath.Join(e.paths.State, state.FileName) }

// loadConfig reads tender.yaml. A missing file is an empty config: every
// reader is off.
func (e *env) loadConfig() (*config.Config, error) {
	c, err := config.Load(e.paths.Config)
	if errors.Is(err, os.ErrNotExist) {
		return &config.Config{}, nil
	}
	return c, err
}

// endpoints pairs each reader that is on with the reader this build
// carries. A name this build does not carry is logged and skipped.
func (e *env) endpoints(c *config.Config) []agent.Endpoint {
	var out []agent.Endpoint
	for _, ep := range c.Endpoints() {
		r, ok := Readers[ep.Name]
		if !ok {
			e.log.Warn("reader not in this build", "reader", ep.Name)
			continue
		}
		out = append(out, agent.Endpoint{Endpoint: ep, Reader: r})
	}
	return out
}

func (e *env) newAgent(c *config.Config, st *state.State, keys *keyring) *agent.Agent {
	return &agent.Agent{
		Endpoints: e.endpoints(c),
		Key:       keys.Key,
		HTTP:      &http.Client{Timeout: 60 * time.Second},
		State:     st,
		Now:       e.now,
		UserAgent: "tender/" + Version,
		Log:       e.log,
	}
}

// keyring loads the identity and keeps it a while, so a certificate that
// device management replaces is picked up within minutes.
type keyring struct {
	mu       sync.Mutex
	cfg      config.Identity
	stateDir string
	now      func() time.Time
	id       *identity.Identity
	at       time.Time
}

const identityTTL = 10 * time.Minute

func (k *keyring) Identity() (*identity.Identity, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if k.id != nil && now.Sub(k.at) < identityTTL && now.Before(k.id.Leaf().NotAfter) {
		return k.id, nil
	}
	id, err := identity.Load(k.cfg, k.stateDir, now)
	if err != nil {
		k.id = nil
		return nil, err
	}
	k.id, k.at = id, now
	return id, nil
}

func (k *keyring) Key(context.Context) (assertion.Key, error) {
	id, err := k.Identity()
	if err != nil {
		return assertion.Key{}, err
	}
	return id.Key(), nil
}

// forget drops the cached identity, after a renewal.
func (k *keyring) forget() {
	k.mu.Lock()
	k.id = nil
	k.mu.Unlock()
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Package e2e runs Tender against a member's real door: platformkit's
// device package, with an in-memory device authority, Tender's file-key
// signer, and Muster's reader over a git repository made for the test.
package e2e

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/orchard-suite/platformkit/v3/device"
	"github.com/orchard-suite/platformkit/v3/device/devicetest"
	"go.step.sm/crypto/pemutil"

	"github.com/orchard-suite/tender/internal/agent"
	"github.com/orchard-suite/tender/internal/assertion"
	"github.com/orchard-suite/tender/internal/config"
	"github.com/orchard-suite/tender/internal/identity"
	"github.com/orchard-suite/tender/internal/readers/muster"
	"github.com/orchard-suite/tender/internal/state"
)

// member is a member with Tender's two calls behind the door.
type member struct {
	mu      sync.Mutex
	srv     *httptest.Server
	got     []agent.Envelope
	devices []device.Device
}

func newMember(t *testing.T, auth *devicetest.Authority) *member {
	m := &member{}
	var h http.Handler
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(m.srv.Close)
	door, err := device.New(device.Config{Audience: m.srv.URL, Roots: auth.Roots, HTTP: auth.Server.Client()}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tender/v1/readers/muster", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"accept":true,"version":1,"every":"15m"}`)
	})
	mux.HandleFunc("POST /tender/v1/readers/muster", func(w http.ResponseWriter, r *http.Request) {
		d, _ := device.From(r.Context())
		var env agent.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		m.mu.Lock()
		m.got, m.devices = append(m.got, env), append(m.devices, d)
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	h = door.Wrap(mux)
	return m
}

// writeIdentity puts an issued key and chain in a key file and a cert
// file, as an estate with no store holds them, and loads them back
// through Tender's file store.
func writeIdentity(t *testing.T, iss devicetest.Issued) func(context.Context) (assertion.Key, error) {
	t.Helper()
	dir := t.TempDir()
	keyPath, certPath := filepath.Join(dir, "device.key"), filepath.Join(dir, "device.crt")
	block, err := pemutil.Serialize(iss.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	var certs []byte
	for _, c := range iss.Chain {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(certPath, certs, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Identity{Key: keyPath, Cert: certPath, Issuer: "CN=Example Devices Issuing CA"}
	return func(context.Context) (assertion.Key, error) {
		id, err := identity.Load(cfg, dir, time.Now())
		if err != nil {
			return assertion.Key{}, err
		}
		return id.Key(), nil
	}
}

// checkouts makes a folder with one git repository in it.
func checkouts(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the path")
	}
	root := t.TempDir()
	repo := filepath.Join(root, "widgets")
	for _, args := range [][]string{
		{"init", "-q", "-b", "main", repo},
		{"-C", repo, "remote", "add", "origin", "https://github.com/acme/widgets.git"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("draft"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func run(t *testing.T, m *member, key func(context.Context) (assertion.Key, error), root string) *agent.Agent {
	t.Helper()
	cfg, err := config.Parse([]byte("readers:\n  muster:\n    address: " + m.srv.URL + "\n    settings: { roots: [\"" + filepath.ToSlash(root) + "\"] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	a := &agent.Agent{
		Endpoints: []agent.Endpoint{{Endpoint: cfg.Endpoints()[0], Reader: muster.Reader{}}},
		Key:       key,
		HTTP:      m.srv.Client(),
		State:     &state.State{},
		Now:       time.Now,
	}
	a.Tick(context.Background())
	return a
}

func TestTheDoorTakesTendersReport(t *testing.T) {
	for _, rsa := range []bool{false, true} {
		name := "ES256"
		if rsa {
			name = "PS256"
		}
		t.Run(name, func(t *testing.T) {
			auth := devicetest.New(t)
			m := newMember(t, auth)
			iss := auth.Issue(t, devicetest.Leaf{CN: "laptop-1", Email: "user@example.com", RSA: rsa})
			a := run(t, m, writeIdentity(t, iss), checkouts(t))

			last := a.State.Reader("muster").Last
			if last.Outcome != agent.Sent || last.Status != http.StatusNoContent {
				t.Fatalf("last = %+v", last)
			}
			if len(m.got) != 1 {
				t.Fatalf("the member got %d reports", len(m.got))
			}
			d := m.devices[0]
			if d.ID != "laptop-1" || d.Person != "user@example.com" {
				t.Errorf("the door named %+v", d)
			}
			var report struct {
				Checkouts []struct {
					Remote    string `json:"remote"`
					Folder    string `json:"folder"`
					Untracked int    `json:"untracked"`
				} `json:"checkouts"`
			}
			if err := json.Unmarshal(m.got[0].Report, &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Checkouts) != 1 || report.Checkouts[0].Remote != "github.com/acme/widgets" || report.Checkouts[0].Untracked != 1 {
				t.Errorf("report = %+v", report)
			}
		})
	}
}

func TestTheDoorRefusesARevokedDevice(t *testing.T) {
	auth := devicetest.New(t)
	m := newMember(t, auth)
	iss := auth.Issue(t, devicetest.Leaf{CN: "laptop-1", Email: "user@example.com"})
	auth.Revoke(iss.Cert)
	a := run(t, m, writeIdentity(t, iss), checkouts(t))
	last := a.State.Reader("muster").Last
	if last.Outcome != agent.Failed || last.Status != http.StatusUnauthorized || len(m.got) != 0 {
		t.Errorf("a revoked device got through: %+v, %d reports", last, len(m.got))
	}
}

func TestTheChainLeavesOutTheRoot(t *testing.T) {
	auth := devicetest.New(t)
	iss := auth.Issue(t, devicetest.Leaf{})
	key, err := writeIdentity(t, iss)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range key.Chain {
		if c.Equal(auth.Root) {
			t.Error("the chain Tender sends holds the root")
		}
	}
	if !key.Chain[0].Equal(iss.Cert) {
		t.Error("the device certificate is not first")
	}
}

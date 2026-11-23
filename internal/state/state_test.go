package state_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/orchard-suite/tender/internal/state"
)

func TestMissingFileIsEmpty(t *testing.T) {
	s, err := state.Load(filepath.Join(t.TempDir(), "none", state.FileName))
	if err != nil || len(s.Readers) != 0 {
		t.Fatalf("got %+v, %v", s, err)
	}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tender", state.FileName)
	due := time.Date(2026, 11, 23, 14, 15, 0, 0, time.UTC)
	s := &state.State{}
	r := s.Reader("muster")
	r.Answer = &state.Answer{Accept: true, Version: 1, Every: "15m"}
	r.NextDue = due
	r.Last = &state.Result{At: due.Add(-15 * time.Minute), Outcome: "sent", Status: 204, Version: 1, Bytes: 120, Counts: map[string]int{"checkouts": 3}}
	if err := state.Save(path, s); err != nil {
		t.Fatal(err)
	}
	got, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	g := got.Readers["muster"]
	if g == nil || !g.NextDue.Equal(due) || g.Answer.Every != "15m" || g.Last.Counts["checkouts"] != 3 || g.Last.Status != 204 {
		t.Errorf("round trip lost data: %+v", g)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("a temporary file was left behind: %v", entries)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), state.FileName)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Load(path); err == nil {
		t.Error("a corrupt state file loaded")
	}
}

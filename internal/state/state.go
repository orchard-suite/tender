// Package state keeps Tender's place between runs: each reader's last
// answer from its member, when it is next due, and how its last send went.
package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// FileName is the state file's name inside the state directory.
const FileName = "state.json"

// State is the whole state file.
type State struct {
	Readers map[string]*Reader `json:"readers"`
}

// Reader is one reader's place.
type Reader struct {
	Answer  *Answer   `json:"answer,omitempty"`  // the member's last answer to the ask
	AskedAt time.Time `json:"asked_at,omitzero"` // when it gave it
	NextDue time.Time `json:"next_due,omitzero"` // when to ask, read, and send next
	Last    *Result   `json:"last,omitempty"`    // how the last ask or send went
	LastOK  time.Time `json:"last_ok,omitzero"`  // when a report was last taken
}

// Answer is a member's answer to the ask.
type Answer struct {
	Accept  bool   `json:"accept"`
	Version int    `json:"version,omitempty"`
	Every   string `json:"every,omitempty"`
	Retry   string `json:"retry,omitempty"`
}

// Result is how one ask or send went. It holds names and counts only.
type Result struct {
	At      time.Time      `json:"at"`
	Outcome string         `json:"outcome"` // sent, declined, unsupported, refused, held, failed
	Status  int            `json:"status,omitempty"`
	Version int            `json:"version,omitempty"`
	Bytes   int            `json:"bytes,omitempty"`
	Counts  map[string]int `json:"counts,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// Reader returns a reader's place, making it when it is new.
func (s *State) Reader(name string) *Reader {
	if s.Readers == nil {
		s.Readers = map[string]*Reader{}
	}
	r, ok := s.Readers[name]
	if !ok {
		r = &Reader{}
		s.Readers[name] = r
	}
	return r
}

// Load reads a state file. A missing file is an empty state.
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &State{Readers: map[string]*Reader{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Readers == nil {
		s.Readers = map[string]*Reader{}
	}
	return &s, nil
}

// Save writes a state file whole, through a temporary file, so a crash
// never leaves half a file.
func Save(path string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(b, '\n'))
}

// WriteFile writes a file only its user can read, atomically.
func WriteFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

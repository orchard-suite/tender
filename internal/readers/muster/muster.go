// Package muster carries Muster's reader, which lives in Muster's own
// repository, behind Tender's reader interface.
package muster

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/orchard-suite/muster/reader"
)

// Settings are the reader's settings in tender.yaml. A root may start
// with ~.
type Settings struct {
	Roots  []string `yaml:"roots"`
	Ignore []string `yaml:"ignore"`
}

// Reader is Muster's reader.
type Reader struct{}

func (Reader) Name() string { return reader.Name }

func (Reader) Versions() []int { return []int{reader.Version} }

func (Reader) Read(ctx context.Context, version int, settings yaml.Node) (any, error) {
	if version != reader.Version {
		return nil, fmt.Errorf("muster: cannot write version %d", version)
	}
	var s Settings
	if !settings.IsZero() {
		if err := settings.Decode(&s); err != nil {
			return nil, fmt.Errorf("muster settings: %w", err)
		}
	}
	return reader.Read(ctx, reader.Config{Roots: s.Roots, Ignore: s.Ignore})
}

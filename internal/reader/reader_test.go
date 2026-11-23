package reader_test

import (
	"strings"
	"testing"

	"github.com/orchard-suite/tender/internal/reader"
)

func TestStringLimit(t *testing.T) {
	ok := map[string]any{"checkouts": []any{map[string]any{"folder": strings.Repeat("a", reader.MaxString)}}}
	if _, err := reader.Encode(ok); err != nil {
		t.Errorf("a %d-byte string was refused: %v", reader.MaxString, err)
	}

	long := strings.Repeat("a", reader.MaxString+1)
	for name, report := range map[string]any{
		"value":      map[string]any{"checkouts": []any{map[string]any{"folder": long}}},
		"key":        map[string]any{long: 1},
		"nested":     []any{[]any{[]any{long}}},
		"multi-byte": map[string]string{"name": strings.Repeat("é", reader.MaxString/2+1)},
	} {
		_, err := reader.Encode(report)
		if err == nil {
			t.Errorf("%s: a string over the limit was sent", name)
			continue
		}
		if strings.Contains(err.Error(), "aaaa") {
			t.Errorf("%s: the error repeats the string: %v", name, err)
		}
	}
}

func TestCountsNameListsOnly(t *testing.T) {
	raw, err := reader.Encode(map[string]any{
		"scanned_at": "2026-11-23T14:00:00Z",
		"checkouts":  []any{1, 2, 3},
		"machines":   []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := reader.FormatCounts(reader.Counts(raw))
	if got != "checkouts=3 machines=0" {
		t.Errorf("counts = %q", got)
	}
}

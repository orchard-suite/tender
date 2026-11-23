// Package reader is the interface every reader Tender carries meets, and
// the rule Tender holds every report to.
package reader

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// Reader reads one member's report from this machine. Each member owns its
// reader, in its own repository; Tender compiles it in behind this
// interface.
type Reader interface {
	Name() string
	Versions() []int // report versions it can write
	Read(ctx context.Context, version int, settings yaml.Node) (any, error)
}

// MaxString is the longest string a report may hold, in bytes. Reports
// carry names and counts; anything longer is refused.
const MaxString = 512

// Supports reports whether r can write version v.
func Supports(r Reader, v int) bool {
	for _, have := range r.Versions() {
		if have == v {
			return true
		}
	}
	return false
}

// Encode marshals a report and holds it to names and counts: it refuses a
// report whose JSON holds a string, or an object key, longer than
// MaxString bytes. The error says how long, never what the string was.
func Encode(report any) (json.RawMessage, error) {
	b, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if n := longest(v); n > MaxString {
		return nil, fmt.Errorf("the report holds a string of %d bytes; the limit is %d", n, MaxString)
	}
	return b, nil
}

func longest(v any) int {
	n := 0
	switch t := v.(type) {
	case string:
		n = len(t)
	case []any:
		for _, e := range t {
			n = max(n, longest(e))
		}
	case map[string]any:
		for k, e := range t {
			n = max(n, len(k), longest(e))
		}
	}
	return n
}

// Counts sums up a report for people: each top-level list and its length.
// It names fields, never values.
func Counts(report json.RawMessage) map[string]int {
	var top map[string]json.RawMessage
	if json.Unmarshal(report, &top) != nil {
		return nil
	}
	out := map[string]int{}
	for k, raw := range top {
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) == nil && list != nil {
			out[k] = len(list)
		}
	}
	return out
}

// FormatCounts prints counts in a stable order: "checkouts=12 machines=1".
func FormatCounts(c map[string]int) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(' ')
		}
		fmt.Fprintf(&buf, "%s=%d", k, c[k])
	}
	return buf.String()
}

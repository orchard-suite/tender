package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLoggerWritesTimestamp(t *testing.T) {
	var buf bytes.Buffer
	newLogger(&buf, "once").Info("sent")
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	if _, ok := line["timestamp"]; !ok {
		t.Errorf("no timestamp in %v", line)
	}
	if _, ok := line["time"]; ok {
		t.Errorf("time key still present in %v", line)
	}
}

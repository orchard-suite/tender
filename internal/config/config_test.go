package config_test

import (
	"strings"
	"testing"

	"github.com/orchard-suite/tender/internal/config"
)

const sample = `
identity:
  issuer: "CN=Example Devices Issuing CA"
readers:
  muster:
    address: https://muster.example.com
    settings: { roots: ["~/source"], ignore: ["node_modules"] }
  tally:
    settings: { every: 1 }
`

func TestReadsTheBriefsConfig(t *testing.T) {
	c, err := config.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.Identity.Issuer != "CN=Example Devices Issuing CA" || c.Identity.Files() {
		t.Errorf("identity = %+v", c.Identity)
	}
	eps := c.Endpoints()
	if len(eps) != 1 || eps[0].Name != "muster" {
		t.Fatalf("endpoints = %+v; a reader with no address must be off", eps)
	}
	if got := eps[0].URL.String(); got != "https://muster.example.com/tender/v1/readers/muster" {
		t.Errorf("url = %s", got)
	}
	if got := eps[0].Audience(); got != "https://muster.example.com" {
		t.Errorf("audience = %s", got)
	}
	var s struct {
		Roots  []string `yaml:"roots"`
		Ignore []string `yaml:"ignore"`
	}
	if err := eps[0].Settings.Decode(&s); err != nil || s.Roots[0] != "~/source" || s.Ignore[0] != "node_modules" {
		t.Errorf("settings = %+v, %v", s, err)
	}
}

func TestKeyAndCertFiles(t *testing.T) {
	c, err := config.Parse([]byte("identity:\n  key: /k.pem\n  cert: /c.pem\n"))
	if err != nil || !c.Identity.Files() {
		t.Fatalf("files: %+v %v", c, err)
	}
}

func TestEmptyConfigIsAllOff(t *testing.T) {
	c, err := config.Parse(nil)
	if err != nil || len(c.Endpoints()) != 0 {
		t.Fatalf("empty: %+v %v", c, err)
	}
}

func TestRefusals(t *testing.T) {
	for name, doc := range map[string]string{
		"key without cert":   "identity:\n  key: /k.pem\n",
		"plain http":         "readers:\n  muster:\n    address: http://muster.example.com\n",
		"query":              "readers:\n  muster:\n    address: https://muster.example.com/?a=b\n",
		"unknown field":      "identity:\n  isuer: x\n",
		"not a url":          "readers:\n  muster:\n    address: muster.example.com\n",
		"credentials in url": "readers:\n  muster:\n    address: https://a:b@muster.example.com\n",
	} {
		if _, err := config.Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := config.Parse([]byte("readers:\n  muster:\n    address: http://127.0.0.1:8080\n")); err != nil {
		t.Errorf("loopback http refused: %v", err)
	}
}

func TestExpandHome(t *testing.T) {
	if got := config.ExpandHome("~/source"); strings.HasPrefix(got, "~") {
		t.Errorf("~ not expanded: %s", got)
	}
	if got := config.ExpandHome("/abs"); got != "/abs" {
		t.Errorf("absolute path changed: %s", got)
	}
}

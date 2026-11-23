// Package config reads tender.yaml and says where Tender keeps its files on
// each operating system.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the config file's name inside the config directory.
const FileName = "tender.yaml"

// Config is the whole of tender.yaml.
type Config struct {
	Identity Identity          `yaml:"identity"`
	Readers  map[string]Reader `yaml:"readers"`
}

// Identity says which certificate and key Tender signs with. Issuer picks
// the store identity that issuer signed. Key and Cert name files instead,
// for an operating system with no store.
type Identity struct {
	Issuer string `yaml:"issuer"`
	Key    string `yaml:"key"`
	Cert   string `yaml:"cert"`
}

// Files reports whether the identity names a key file and a cert file.
func (i Identity) Files() bool { return i.Key != "" || i.Cert != "" }

// Reader is one reader's entry. A reader with no address is off.
type Reader struct {
	Address  string    `yaml:"address"`
	Settings yaml.Node `yaml:"settings"`
}

// Endpoint is a reader that is on: its name, where it posts, and its own
// settings, still undecoded.
type Endpoint struct {
	Name     string
	URL      *url.URL // the address with /tender/v1/readers/<name> joined on
	Settings yaml.Node
}

// Audience is the member's origin: scheme and host, no path.
func (e Endpoint) Audience() string { return e.URL.Scheme + "://" + e.URL.Host }

// Load reads and checks a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and checks config bytes.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("tender.yaml: %w", err)
	}
	if c.Identity.Files() && (c.Identity.Key == "" || c.Identity.Cert == "") {
		return nil, errors.New("tender.yaml: identity needs both key and cert, or neither")
	}
	for name, r := range c.Readers {
		if r.Address == "" {
			continue
		}
		if _, err := endpointURL(r.Address, name); err != nil {
			return nil, fmt.Errorf("tender.yaml: reader %s: %w", name, err)
		}
	}
	return &c, nil
}

// Endpoints lists the readers that are on, sorted by name.
func (c *Config) Endpoints() []Endpoint {
	names := make([]string, 0, len(c.Readers))
	for name, r := range c.Readers {
		if r.Address != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]Endpoint, 0, len(names))
	for _, name := range names {
		r := c.Readers[name]
		u, _ := endpointURL(r.Address, name) // checked by Parse
		out = append(out, Endpoint{Name: name, URL: u, Settings: r.Settings})
	}
	return out
}

// endpointURL joins a member's address and a reader's name. The address
// must be https; plain http is allowed only to this machine, for tests.
func endpointURL(address, name string) (*url.URL, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	if u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("address %q must be a plain origin such as https://member.example.com", address)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, fmt.Errorf("address %q must use https", address)
		}
	default:
		return nil, fmt.Errorf("address %q must use https", address)
	}
	return u.JoinPath("tender", "v1", "readers", name), nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ExpandHome turns a leading ~ into the user's home folder.
func ExpandHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[1:])
}

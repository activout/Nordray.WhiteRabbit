// Package config selects the White Rabbit environment (server) a command talks to.
//
// Environments are named in a small JSON file (rabbit env add/use/remove). The choice is explicit: a flag
// (--env, --server), an environment variable (RABBIT_ENV, RABBIT_SERVER) or the file's current environment.
// When nothing is selected and more than one environment exists, commands fail instead of guessing.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// File is the on-disk configuration. It holds names and URLs only, never credentials.
type File struct {
	Current      string                 `json:"current,omitempty"`
	Environments map[string]Environment `json:"environments"`
}

// Environment is one White Rabbit server.
type Environment struct {
	URL string `json:"url"`
}

// Selected is the environment a command will use, and why.
type Selected struct {
	Name   string // empty for an ad hoc --server/RABBIT_SERVER
	URL    string // normalised: scheme://host[:port], no trailing slash
	Source string // "--env", "RABBIT_SERVER", "current environment", ...
}

// Label is shown to the user so the target is always visible.
func (s Selected) Label() string {
	if s.Name == "" {
		return s.URL
	}
	return fmt.Sprintf("%s (%s)", s.Name, s.URL)
}

// Path is the configuration file location: $RABBIT_CONFIG, else <user config dir>/rabbit/config.json.
func Path(getenv func(string) string) (string, error) {
	if p := getenv("RABBIT_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate the configuration directory: %w", err)
	}
	return filepath.Join(dir, "rabbit", "config.json"), nil
}

// Load reads the file; a missing file is an empty configuration.
func Load(path string) (*File, error) {
	f := &File{Environments: map[string]Environment{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Environments == nil {
		f.Environments = map[string]Environment{}
	}
	return f, nil
}

// Save writes the file with owner-only permissions.
func (f *File) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Names returns the environment names, sorted.
func (f *File) Names() []string {
	names := make([]string, 0, len(f.Environments))
	for n := range f.Environments {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Select picks the environment from, in order: --server, --env, RABBIT_SERVER, RABBIT_ENV, the current
// environment, or the only configured environment. Anything ambiguous is an error.
func Select(f *File, flagEnv, flagServer string, getenv func(string) string) (Selected, error) {
	if flagEnv != "" && flagServer != "" {
		return Selected{}, errors.New("use either --env or --server, not both")
	}
	if flagServer != "" {
		return adHoc(flagServer, "--server")
	}
	if flagEnv != "" {
		return named(f, flagEnv, "--env")
	}
	if s := getenv("RABBIT_SERVER"); s != "" {
		if getenv("RABBIT_ENV") != "" {
			return Selected{}, errors.New("RABBIT_SERVER and RABBIT_ENV are both set; set only one")
		}
		return adHoc(s, "RABBIT_SERVER")
	}
	if e := getenv("RABBIT_ENV"); e != "" {
		return named(f, e, "RABBIT_ENV")
	}
	if f.Current != "" {
		return named(f, f.Current, "current environment")
	}
	switch len(f.Environments) {
	case 0:
		return Selected{}, errors.New("no White Rabbit server configured: run `rabbit env add <name> <url>`, or set RABBIT_SERVER")
	case 1:
		return named(f, f.Names()[0], "only environment")
	default:
		return Selected{}, fmt.Errorf("several environments are configured (%s) and none is selected: use --env, RABBIT_ENV or `rabbit env use <name>`",
			strings.Join(f.Names(), ", "))
	}
}

func named(f *File, name, source string) (Selected, error) {
	e, ok := f.Environments[name]
	if !ok {
		return Selected{}, fmt.Errorf("unknown environment %q (configured: %s)", name, strings.Join(f.Names(), ", "))
	}
	u, err := NormalizeURL(e.URL)
	if err != nil {
		return Selected{}, fmt.Errorf("environment %q: %w", name, err)
	}
	return Selected{Name: name, URL: u, Source: source}, nil
}

func adHoc(raw, source string) (Selected, error) {
	u, err := NormalizeURL(raw)
	if err != nil {
		return Selected{}, fmt.Errorf("%s: %w", source, err)
	}
	return Selected{URL: u, Source: source}, nil
}

// NormalizeURL accepts only a bare origin. HTTPS is required, except for loopback hosts during local development,
// so session tokens and virtual credentials are never sent in clear over a network.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("server URL %q must be just scheme://host[:port]", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !IsLoopback(u.Hostname()) {
			return "", fmt.Errorf("server URL %q must use https (http is allowed only for localhost)", raw)
		}
	default:
		return "", fmt.Errorf("server URL %q must use https", raw)
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

// IsLoopback reports whether host is localhost or a loopback IP.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

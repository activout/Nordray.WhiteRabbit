package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestNormalizeURL(t *testing.T) {
	ok := map[string]string{
		"https://WhiteRabbit.Example.com":  "https://whiterabbit.example.com",
		"https://whiterabbit.example.com/": "https://whiterabbit.example.com",
		"https://example.com:8443":         "https://example.com:8443",
		"http://localhost:8080":            "http://localhost:8080",
		"http://127.0.0.1:8080":            "http://127.0.0.1:8080",
	}
	for in, want := range ok {
		got, err := NormalizeURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"http://whiterabbit.example.com", // clear text off loopback
		"ftp://example.com",
		"https://user:pass@example.com",
		"https://example.com/proxy",
		"https://example.com?x=1",
		"example.com",
		"",
	} {
		if _, err := NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) accepted", bad)
		}
	}
}

func TestSelectPrecedenceAndAmbiguity(t *testing.T) {
	f := &File{Environments: map[string]Environment{
		"prod": {URL: "https://wr.example.com"},
		"test": {URL: "https://wr.test.example.com"},
	}}

	if _, err := Select(f, "", "", env(nil)); err == nil || !strings.Contains(err.Error(), "none is selected") {
		t.Fatalf("two environments without a selection must fail, got %v", err)
	}
	f.Current = "prod"
	cases := []struct {
		name, flagEnv, flagServer string
		vars                      map[string]string
		want                      string
	}{
		{"current", "", "", nil, "https://wr.example.com"},
		{"RABBIT_ENV", "", "", map[string]string{"RABBIT_ENV": "test"}, "https://wr.test.example.com"},
		{"RABBIT_SERVER", "", "", map[string]string{"RABBIT_SERVER": "https://other.example.com"}, "https://other.example.com"},
		{"--env beats variables", "test", "", map[string]string{"RABBIT_SERVER": "https://other.example.com"}, "https://wr.test.example.com"},
		{"--server", "", "https://adhoc.example.com", nil, "https://adhoc.example.com"},
	}
	for _, c := range cases {
		got, err := Select(f, c.flagEnv, c.flagServer, env(c.vars))
		if err != nil || got.URL != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got.URL, err, c.want)
		}
	}
	if _, err := Select(f, "test", "https://x.example.com", env(nil)); err == nil {
		t.Error("--env and --server together must fail")
	}
	if _, err := Select(f, "", "", env(map[string]string{"RABBIT_SERVER": "https://a.example.com", "RABBIT_ENV": "prod"})); err == nil {
		t.Error("RABBIT_SERVER and RABBIT_ENV together must fail")
	}
	if _, err := Select(f, "staging", "", env(nil)); err == nil {
		t.Error("unknown environment must fail")
	}
	if _, err := Select(&File{Environments: map[string]Environment{}}, "", "", env(nil)); err == nil {
		t.Error("no environment must fail")
	}
	only := &File{Environments: map[string]Environment{"prod": {URL: "https://wr.example.com"}}}
	if got, err := Select(only, "", "", env(nil)); err != nil || got.Name != "prod" {
		t.Errorf("a single environment is unambiguous, got %v %v", got, err)
	}
}

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rabbit", "config.json")
	f := &File{Current: "prod", Environments: map[string]Environment{"prod": {URL: "https://wr.example.com"}}}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	g, err := Load(path)
	if err != nil || g.Current != "prod" || g.Environments["prod"].URL != "https://wr.example.com" {
		t.Fatalf("round trip failed: %+v %v", g, err)
	}
}

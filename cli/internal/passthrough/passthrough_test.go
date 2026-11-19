package passthrough

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMapPath(t *testing.T) {
	cases := map[string]string{
		"/v2/databases":                 "/database/v2/databases",
		"/v1/config":                    "/database/v1/config",
		"/v1/config/optimal":            "/database/v1/config/optimal",
		"/v1/databases/abc/auth/tokens": "/database/v1/databases/abc/auth/tokens",
		"/v1/groups/1/stats":            "/database/v1/groups/1/stats",
		"/v1/pricing/a/b":               "/v1/pricing/a/b", // core API
		"/apps":                         "/mc/apps",
		"/apps/123/containers/9":        "/mc/apps/123/containers/9",
		"/registries":                   "/mc/registries",
		"/regions":                      "/mc/regions",
		"/region":                       "/region", // core API, singular
		"/appsx":                        "/appsx",
		"/pullzone":                     "/pullzone",
		"/mc/apps":                      "/mc/apps",      // bunny api, already prefixed
		"/database/v2/databases":        "/database/v2/databases",
		"":                              "/",
	}
	for in, want := range cases {
		if got := MapPath(in); got != want {
			t.Errorf("MapPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChildEnvRemovesCredentialsAndPinsLoopback(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin",
		"HOME=/home/me",
		"BUNNYNET_API_KEY=real-key",
		"BUNNYNET_API_URL=https://api.bunny.net",
		"BUNNY_STORAGE_PASSWORD=zone-password",
		"bunnynet_api_key=lowercase-real-key",
		"GITHUB_TOKEN=ghs_x",
		"FORGEJO_TOKEN=f",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN=t",
		"ACTIONS_RUNTIME_TOKEN=r",
		"RABBIT_SERVER=https://wr.example.com",
		"HTTPS_PROXY=http://proxy:3128",
		"NO_PROXY=.corp.example",
	}
	got := ChildEnv(parent, "http://127.0.0.1:5000", "rabbit-local-x")
	joined := "\n" + strings.Join(got, "\n") + "\n"
	for _, secret := range []string{"real-key", "zone-password", "ghs_x", "FORGEJO_TOKEN", "ACTIONS_ID_TOKEN", "ACTIONS_RUNTIME", "RABBIT_SERVER", "https://api.bunny.net"} {
		if strings.Contains(joined, secret) {
			t.Errorf("child environment still contains %q", secret)
		}
	}
	for _, want := range []string{
		"\nPATH=/usr/bin\n",
		"\nHTTPS_PROXY=http://proxy:3128\n",
		"\nBUNNYNET_API_URL=http://127.0.0.1:5000\n",
		"\nBUNNYNET_API_KEY=rabbit-local-x\n",
		"\nBUNNYNET_DASHBOARD_URL=http://127.0.0.1:1\n",
		"\nNO_PROXY=.corp.example,127.0.0.1,localhost,::1\n",
		"\nno_proxy=.corp.example,127.0.0.1,localhost,::1\n",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("child environment lacks %q", strings.TrimSpace(want))
		}
	}
}

func TestCheckArgsRefusesApiKey(t *testing.T) {
	for _, args := range [][]string{{"--api-key", "x", "whoami"}, {"--api-key=x"}} {
		if CheckArgs(args) == nil {
			t.Errorf("%v accepted", args)
		}
	}
	if CheckArgs([]string{"api", "GET", "/pullzone", "--output", "json"}) != nil {
		t.Error("ordinary arguments refused")
	}
}

func TestForwarder(t *testing.T) {
	var issued atomic.Int32
	var seen atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Clone(context.Background()))
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))
	defer upstream.Close()

	source := func(context.Context) (string, time.Time, error) {
		n := issued.Add(1)
		// The first credential is about to expire, so the second request must get a new one.
		if n == 1 {
			return "wrk_first", time.Now().Add(30 * time.Second), nil
		}
		return "wrk_second", time.Now().Add(5 * time.Minute), nil
	}
	f, err := StartForwarder(upstream.URL, source, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	get := func(path, key string, extra map[string]string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, f.URL+path, nil)
		if key != "" {
			req.Header.Set("AccessKey", key)
		}
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	if resp, _ := get("/pullzone", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no local key: got %d", resp.StatusCode)
	}
	if resp, _ := get("/pullzone", "real-bunny-key", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong local key: got %d", resp.StatusCode)
	}
	if issued.Load() != 0 {
		t.Fatal("a credential was requested for an unauthenticated local request")
	}

	resp, body := get("/v2/databases?page=1", f.LocalKey, map[string]string{"Authorization": "Bearer stolen", "Cookie": "a=b"})
	if resp.StatusCode != http.StatusOK || body != "/proxy/api.bunny.net/database/v2/databases?page=1" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	r := seen.Load().(*http.Request)
	if r.Header.Get("AccessKey") != "wrk_first" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		t.Fatalf("upstream headers: AccessKey=%q Authorization=%q Cookie=%q", r.Header.Get("AccessKey"), r.Header.Get("Authorization"), r.Header.Get("Cookie"))
	}

	get("/pullzone", f.LocalKey, nil)
	if r := seen.Load().(*http.Request); r.Header.Get("AccessKey") != "wrk_second" {
		t.Fatalf("a credential within a minute of expiry was not renewed: %q", r.Header.Get("AccessKey"))
	}
	get("/pullzone", f.LocalKey, nil)
	if issued.Load() != 2 {
		t.Fatalf("a valid credential must be reused, issued %d", issued.Load())
	}
}

func TestForwarderWithoutCredentialAnswers401(t *testing.T) {
	f, err := StartForwarder("http://127.0.0.1:9", func(context.Context) (string, time.Time, error) {
		return "", time.Time{}, errors.New("not signed in")
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	req, _ := http.NewRequest(http.MethodGet, f.URL+"/pullzone", nil)
	req.Header.Set("AccessKey", f.LocalKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestNativeFromNpmLauncher(t *testing.T) {
	for _, layout := range []string{"hoisted", "nested"} {
		t.Run(layout, func(t *testing.T) {
			prefix := t.TempDir()
			launcher := filepath.Join(prefix, "bunny.cmd")
			if err := os.WriteFile(launcher, []byte("@echo off"), 0o644); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(prefix, "node_modules", "@bunny.net", "cli-windows-x64")
			if layout == "nested" {
				dir = filepath.Join(prefix, "node_modules", "@bunny.net", "cli", "node_modules", "@bunny.net", "cli-windows-x64")
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			exe := filepath.Join(dir, "bunny.exe")
			if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
				t.Fatal(err)
			}
			got, ok := NativeFromNpmLauncher(launcher, "amd64")
			if !ok || got != exe {
				t.Fatalf("got %q %v, want %q", got, ok, exe)
			}
			if _, ok := NativeFromNpmLauncher(launcher, "arm64"); ok {
				t.Fatal("arm64 must not resolve the x64 binary")
			}
		})
	}
	if _, ok := NativeFromNpmLauncher(filepath.Join(t.TempDir(), "bunny.cmd"), "amd64"); ok {
		t.Fatal("a launcher without the native package must not resolve")
	}
}

func TestIsScriptLauncher(t *testing.T) {
	for path, want := range map[string]bool{`C:\npm\bunny.cmd`: true, `C:\npm\BUNNY.BAT`: true, `C:\npm\bunny.ps1`: true, `C:\bin\bunny.exe`: false, "/usr/bin/bunny": false} {
		if got := isScriptLauncher(path); got != want {
			t.Errorf("isScriptLauncher(%q) = %v", path, got)
		}
	}
}

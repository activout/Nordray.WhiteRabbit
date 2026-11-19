package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/activout/nordray.whiterabbit/cli/internal/secrets"
)

// TestMain lets the test binary double as a fake BunnyCLI: rabbit starts it as the child process.
func TestMain(m *testing.M) {
	if os.Getenv("FAKE_BUNNY") == "1" {
		os.Exit(fakeBunny(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeBunny reports what the child sees: its arguments, credential variables, and the result of an API call
// through BUNNYNET_API_URL, as BunnyCLI would make it.
func fakeBunny(args []string) int {
	fmt.Printf("ARGS:%s\n", strings.Join(args, " "))
	for _, name := range []string{"BUNNYNET_API_KEY", "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "BUNNY_STORAGE_PASSWORD", "RABBIT_SERVER"} {
		fmt.Printf("ENV:%s=%s\n", name, os.Getenv(name))
	}
	code := 0
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "call" && i+1 < len(args):
			req, _ := http.NewRequest(http.MethodGet, os.Getenv("BUNNYNET_API_URL")+args[i+1], nil)
			req.Header.Set("AccessKey", os.Getenv("BUNNYNET_API_KEY"))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Println("CALL-ERROR:", err)
				return 99
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Printf("STATUS:%d BODY:%s\n", resp.StatusCode, body)
			i++
		case args[i] == "stdin":
			data, _ := io.ReadAll(os.Stdin)
			fmt.Printf("STDIN:%s\n", data)
		case strings.HasPrefix(args[i], "exit="):
			code, _ = strconv.Atoi(strings.TrimPrefix(args[i], "exit="))
		}
	}
	return code
}

// fakeWhiteRabbit implements the CLI API and the proxy, plus a CI token endpoint.
func fakeWhiteRabbit(t *testing.T) *httptest.Server {
	t.Helper()
	sessions := map[string]string{"wrs_human": "human", "wrs_ci": "github_workload"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/cli/config", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"dex_client_id":"rabbit-cli","federation_audience":"whiterabbit:test","capabilities":[{"name":"statistics.read"}]}`)
	})
	mux.HandleFunc("/idtoken", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer job-request-token" || r.URL.Query().Get("audience") != "whiterabbit:test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"value":"ci-id-token"}`)
	})
	mux.HandleFunc("/api/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["subject_token"] != "ci-id-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"access_denied","reason":"no_matching_binding"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "wrs_ci", "expires_at": time.Now().Add(time.Hour),
			"principal": map[string]any{"type": "github_workload", "repository": "acme/app"}})
	})
	authed := func(r *http.Request) string { return sessions[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] }
	mux.HandleFunc("/api/cli/credentials", func(w http.ResponseWriter, r *http.Request) {
		if authed(r) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_key": "wrk_test", "credential_id": "c1", "expires_at": time.Now().Add(5 * time.Minute)})
	})
	mux.HandleFunc("/api/cli/whoami", func(w http.ResponseWriter, r *http.Request) {
		kind := authed(r)
		if kind == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": kind, "email": map[bool]string{true: "me@example.com"}[kind == "human"],
			"repository": "acme/app", "capabilities": []string{"statistics.read"}, "session_expires_at": time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("/proxy/api.bunny.net/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("AccessKey") != "wrk_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, r.URL.Path)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

type harness struct {
	app            *App
	stdout, stderr *bytes.Buffer
	vars           map[string]string
	server         *httptest.Server
}

func newHarness(t *testing.T) *harness {
	server := fakeWhiteRabbit(t)
	h := &harness{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, server: server, vars: map[string]string{
		"RABBIT_CONFIG": filepath.Join(t.TempDir(), "config.json"),
		"RABBIT_SERVER": server.URL,
		"RABBIT_BUNNY":  os.Args[0],
		"FAKE_BUNNY":    "1",
		"PATH":          os.Getenv("PATH"),
		// Credentials the child must never see:
		"BUNNYNET_API_KEY":       "real-bunny-key",
		"BUNNY_STORAGE_PASSWORD": "zone-password",
	}}
	h.app = &App{
		Stdin: strings.NewReader(""), Stdout: h.stdout, Stderr: h.stderr,
		Getenv:  func(k string) string { return h.vars[k] },
		Secrets: &secrets.Memory{},
	}
	return h
}

func (h *harness) run(args ...string) int {
	h.app.Environ = nil
	for k, v := range h.vars {
		h.app.Environ = append(h.app.Environ, k+"="+v)
	}
	return h.app.Run(context.Background(), args)
}

func (h *harness) inGitHubActions() {
	h.vars["GITHUB_ACTIONS"] = "true"
	h.vars["GITHUB_TOKEN"] = "ghs_secret"
	h.vars["ACTIONS_ID_TOKEN_REQUEST_URL"] = h.server.URL + "/idtoken?api-version=2.0"
	h.vars["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "job-request-token"
}

func TestPassthroughInCI_UsesJobTokenMapsPathAndReturnsExitCode(t *testing.T) {
	h := newHarness(t)
	h.inGitHubActions()

	code := h.run("--", "call", "/v2/databases?page=1", "exit=7")

	out := h.stdout.String()
	if code != 7 {
		t.Fatalf("exit code %d, want the child's 7\nstdout: %s\nstderr: %s", code, out, h.stderr)
	}
	if !strings.Contains(out, "STATUS:200 BODY:/proxy/api.bunny.net/database/v2/databases") {
		t.Fatalf("the call did not reach White Rabbit's proxy with the /database prefix:\n%s", out)
	}
	for _, leak := range []string{"real-bunny-key", "zone-password", "ghs_secret", "job-request-token", "wrk_test", "wrs_ci", "ENV:RABBIT_SERVER=http"} {
		if strings.Contains(out, leak) {
			t.Errorf("the child saw %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "ENV:BUNNYNET_API_KEY=rabbit-local-") {
		t.Errorf("the child did not get a local key:\n%s", out)
	}
}

func TestPassthroughInteractive_PassesArgumentsUnchanged(t *testing.T) {
	h := newHarness(t)
	_ = h.app.Secrets.Set(h.server.URL, secrets.Session{Token: "wrs_human", ExpiresAt: time.Now().Add(time.Hour)})

	if code := h.run("--", "--version"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
	if !strings.Contains(h.stdout.String(), "ARGS:--version\n") {
		t.Fatalf("--version did not reach BunnyCLI:\n%s", h.stdout)
	}

	h.stdout.Reset()
	h.app.Stdin = strings.NewReader("piped input")
	if code := h.run("--", "--help", "stdin", "--", "x y"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
	out := h.stdout.String()
	if !strings.Contains(out, "ARGS:--help stdin -- x y\n") || !strings.Contains(out, "STDIN:piped input") {
		t.Fatalf("arguments or stdin changed:\n%s", out)
	}
}

func TestPassthroughWithoutSession_FailsClosedWithoutStartingBunny(t *testing.T) {
	h := newHarness(t)
	code := h.run("--", "call", "/pullzone")
	if code != 1 || !strings.Contains(h.stderr.String(), "not signed in") || h.stdout.Len() != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, h.stdout, h.stderr)
	}
}

func TestPassthroughExpiredSession_FailsClosed(t *testing.T) {
	h := newHarness(t)
	_ = h.app.Secrets.Set(h.server.URL, secrets.Session{Token: "wrs_human", ExpiresAt: time.Now().Add(-time.Minute)})
	if code := h.run("--", "whoami"); code != 1 || !strings.Contains(h.stderr.String(), "expired") || h.stdout.Len() != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
}

func TestPassthroughRefusesApiKey(t *testing.T) {
	h := newHarness(t)
	if code := h.run("--", "--api-key", "real", "whoami"); code != 2 || h.stdout.Len() != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
}

func TestPassthroughWithoutBunny(t *testing.T) {
	h := newHarness(t)
	h.vars["RABBIT_BUNNY"] = filepath.Join(t.TempDir(), "no-such-bunny")
	if code := h.run("--", "whoami"); code != 1 || !strings.Contains(h.stderr.String(), "BunnyCLI") {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
}

func TestPassthroughCIWithoutTokenPermission_ExplainsTheFix(t *testing.T) {
	h := newHarness(t)
	h.vars["FORGEJO_ACTIONS"] = "true"
	if code := h.run("--", "whoami"); code != 1 || !strings.Contains(h.stderr.String(), "enable-openid-connect") {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
}

func TestWhoAmIInCI(t *testing.T) {
	h := newHarness(t)
	h.inGitHubActions()
	if code := h.run("auth", "whoami"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
	if !strings.Contains(h.stdout.String(), "github_workload") || !strings.Contains(h.stderr.String(), "White Rabbit "+h.server.URL) {
		t.Fatalf("stdout: %s\nstderr: %s", h.stdout, h.stderr)
	}
}

func TestForcedCIOutsideCI_Fails(t *testing.T) {
	h := newHarness(t)
	h.vars["RABBIT_AUTH"] = "ci"
	if code := h.run("auth", "whoami"); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

func TestEnvironmentsAndAmbiguity(t *testing.T) {
	h := newHarness(t)
	delete(h.vars, "RABBIT_SERVER")
	if code := h.run("env", "add", "prod", "https://wr.example.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
	if code := h.run("env", "add", "test", "http://wr.test.example.com"); code != 1 {
		t.Fatal("plain http to a non-loopback host must be refused")
	}
	h.run("env", "add", "test", "https://wr.test.example.com")
	h.stdout.Reset()
	h.run("env", "list")
	if !strings.Contains(h.stdout.String(), "* prod") {
		t.Fatalf("the first environment should be current:\n%s", h.stdout)
	}
	h.run("env", "use", "test")
	h.stdout.Reset()
	h.run("auth", "status")
	if !strings.Contains(h.stdout.String(), "test (https://wr.test.example.com)") {
		t.Fatalf("status must show the selected environment:\n%s", h.stdout)
	}
}

func TestUsage(t *testing.T) {
	h := newHarness(t)
	if code := h.run("--help"); code != 0 || !strings.Contains(h.stdout.String(), "rabbit -- --help") {
		t.Fatal("rabbit --help is rabbit's own help")
	}
	if code := h.run("pullzones", "list"); code != 2 || !strings.Contains(h.stderr.String(), "rabbit -- pullzones") {
		t.Fatalf("unknown commands point at --: %s", h.stderr)
	}
	if code := h.run("--output", "json"); code != 2 {
		t.Fatal("unknown options before -- are errors")
	}
}

func TestLoginRejectsUnknownCapabilityBeforeOpeningTheBrowser(t *testing.T) {
	h := newHarness(t)
	opened := false
	h.app.OpenBrowser = func(string) error { opened = true; return nil }
	code := h.run("auth", "login", "--capabilities", "statistics.read,statistics.reed")
	if code != 2 || opened || !strings.Contains(h.stderr.String(), `unknown capability "statistics.reed"`) {
		t.Fatalf("exit %d, browser opened %v: %s", code, opened, h.stderr)
	}
}

func TestSkillInstall(t *testing.T) {
	h := newHarness(t)
	home := t.TempDir()
	h.vars["HOME"] = home
	claudeSkill := filepath.Join(home, ".claude", "skills", "rabbit", "SKILL.md")
	agentsSkill := filepath.Join(home, ".agents", "skills", "rabbit", "SKILL.md")

	if code := h.run("skill", "install"); code != 1 {
		t.Fatal("with neither ~/.claude nor ~/.agents, install must fail and point at --dir")
	}

	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := h.run("skill", "install"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr)
	}
	got, err := os.ReadFile(claudeSkill)
	if err != nil || !strings.HasPrefix(string(got), "---\nname: rabbit\n") {
		t.Fatalf("SKILL.md at %s: %v %q", claudeSkill, err, got)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents")); err == nil {
		t.Fatal("~/.agents must not be created when it is not in use")
	}

	if err := os.Mkdir(filepath.Join(home, ".agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.run("skill", "install")
	if _, err := os.Stat(agentsSkill); err != nil {
		t.Fatal("an existing ~/.agents must get the skill too:", err)
	}

	h.vars["CLAUDE_CONFIG_DIR"] = t.TempDir()
	h.run("skill", "install")
	if _, err := os.Stat(filepath.Join(h.vars["CLAUDE_CONFIG_DIR"], "skills", "rabbit", "SKILL.md")); err != nil {
		t.Fatal("CLAUDE_CONFIG_DIR must be honoured:", err)
	}

	dir := filepath.Join(t.TempDir(), "agent")
	if code := h.run("skill", "install", "--dir", dir); code != 0 {
		t.Fatalf("--dir: exit %d: %s", code, h.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err != nil {
		t.Fatal(err)
	}

	h.stdout.Reset()
	if code := h.run("skill", "print"); code != 0 || !bytes.Equal(h.stdout.Bytes(), got) {
		t.Fatal("skill print must write the same SKILL.md")
	}
}

func TestHomeDir_PrefersTheProfileOnWindows(t *testing.T) {
	env := map[string]string{"HOME": "/c/Users/me/msys-home", "USERPROFILE": `C:\Users\me`}
	get := func(k string) string { return env[k] }
	if got := homeDir("windows", get); got != `C:\Users\me` {
		t.Fatalf("windows: %q", got)
	}
	if got := homeDir("darwin", get); got != "/c/Users/me/msys-home" {
		t.Fatalf("darwin: %q", got)
	}
	delete(env, "USERPROFILE")
	if got := homeDir("windows", get); got != "/c/Users/me/msys-home" {
		t.Fatalf("windows without USERPROFILE falls back to HOME: %q", got)
	}
}

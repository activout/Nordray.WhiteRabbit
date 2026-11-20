// Package app is the rabbit command line: White Rabbit commands before `--`, BunnyCLI after it.
package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/activout/nordray.whiterabbit/cli/internal/api"
	"github.com/activout/nordray.whiterabbit/cli/internal/ci"
	"github.com/activout/nordray.whiterabbit/cli/internal/config"
	"github.com/activout/nordray.whiterabbit/cli/internal/login"
	"github.com/activout/nordray.whiterabbit/cli/internal/passthrough"
	"github.com/activout/nordray.whiterabbit/cli/internal/secrets"
	"github.com/activout/nordray.whiterabbit/cli/internal/skill"
	"golang.org/x/term"
)

// Version is set at build time with -ldflags "-X .../internal/app.Version=v1.2.3".
var Version = "dev"

// App holds everything a command needs; tests replace the pieces.
type App struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Environ        []string
	Secrets        secrets.Store
	OpenBrowser    func(string) error
	HTTP           *http.Client // nil for the default
	StderrIsTTY    bool
	Self           string // this executable, so RABBIT_BUNNY cannot point at it

	selected     config.Selected
	capabilities string // --capabilities; wins over RABBIT_CAPABILITIES
	ciOnce       sync.Once
	ciToken      string
	ciErr        error
}

// New returns an App wired to the real process.
func New() *App {
	self, _ := os.Executable()
	info, _ := os.Stderr.Stat()
	return &App{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Getenv:      os.Getenv,
		Environ:     os.Environ(),
		Secrets:     secrets.Keyring{},
		OpenBrowser: openBrowser,
		StderrIsTTY: info != nil && info.Mode()&os.ModeCharDevice != 0,
		Self:        self,
	}
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// Run executes the command line and returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	code, err := a.run(ctx, args)
	if err != nil {
		fmt.Fprintln(a.Stderr, "rabbit:", err)
		var u usageError
		if errors.As(err, &u) {
			return 2
		}
		if code == 0 {
			code = 1
		}
	}
	return code
}

func (a *App) run(ctx context.Context, args []string) (int, error) {
	var envFlag, serverFlag string
	i := 0
	for ; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return a.passthrough(ctx, envFlag, serverFlag, args[i+1:])
		case arg == "--env" || arg == "--server" || arg == "--capabilities":
			if i+1 >= len(args) {
				return 2, usageError{arg + " needs a value"}
			}
			switch arg {
			case "--env":
				envFlag = args[i+1]
			case "--server":
				serverFlag = args[i+1]
			default:
				a.capabilities = args[i+1]
			}
			i++
		case strings.HasPrefix(arg, "--capabilities="):
			a.capabilities = strings.TrimPrefix(arg, "--capabilities=")
		case strings.HasPrefix(arg, "--env="):
			envFlag = strings.TrimPrefix(arg, "--env=")
		case strings.HasPrefix(arg, "--server="):
			serverFlag = strings.TrimPrefix(arg, "--server=")
		case arg == "-h" || arg == "--help" || arg == "help":
			fmt.Fprint(a.Stdout, usage)
			return 0, nil
		case arg == "--version" || arg == "version":
			fmt.Fprintf(a.Stdout, "rabbit %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
			return 0, nil
		case strings.HasPrefix(arg, "-"):
			return 2, usageError{fmt.Sprintf("unknown option %s (BunnyCLI options go after `--`)", arg)}
		default:
			return a.command(ctx, envFlag, serverFlag, args[i], args[i+1:])
		}
	}
	fmt.Fprint(a.Stderr, usage)
	return 2, nil
}

const usage = `rabbit: bunny.net through Nordray White Rabbit, without the real bunny.net API key.

Usage:
  rabbit [--env NAME | --server URL] <command>
  rabbit [--env NAME | --server URL] [--capabilities a,b] -- <bunny arguments...>

White Rabbit commands:
  auth login [--no-browser]                        Sign in with the browser (email code + PKCE)
  auth status                                      Show the environment and the session
  auth whoami [--json]                             Show the signed-in user or CI workload
  auth logout                                      Revoke and forget the session
  env list | add NAME URL | use NAME | remove NAME Manage White Rabbit servers
  admin key set | rm                               Store or remove your bunny.net API key (read from stdin)
  admin bindings list | add ... | rm ID            Manage CI workload bindings (interactive session only)
  admin audit [--since 24h] [--binding ID] [--limit N] [--json]
                                                   Show your security events, including your CI workloads
  skill install [--dir DIR] | print                Install the AI agent skill (~/.claude/skills, ~/.agents/skills)
  version

Everything after the first standalone -- is passed unchanged to BunnyCLI (bunny), for example
  rabbit -- whoami
  rabbit -- api GET /pullzone
  rabbit -- --help

In GitHub Actions (permissions: id-token: write) and Forgejo Actions (enable-openid-connect: true) rabbit uses the
job's own OIDC token automatically. Environment: RABBIT_SERVER or RABBIT_ENV select the server, RABBIT_AUTH=ci or
interactive overrides detection, RABBIT_BUNNY points at BunnyCLI, RABBIT_DEBUG=1 logs forwarded requests,
RABBIT_CAPABILITIES=a,b (or --capabilities a,b) limits what the forwarded bunny command may do.
`

func (a *App) command(ctx context.Context, envFlag, serverFlag, name string, args []string) (int, error) {
	switch name {
	case "env":
		return a.envCommand(args)
	case "auth":
		if len(args) == 0 {
			return 2, usageError{"auth needs a subcommand: login, status, whoami or logout"}
		}
		if err := a.selectEnv(envFlag, serverFlag); err != nil {
			return 1, err
		}
		switch args[0] {
		case "login":
			return a.login(ctx, args[1:])
		case "status":
			return a.status(ctx)
		case "whoami":
			return a.whoami(ctx, args[1:])
		case "logout":
			return a.logout(ctx)
		}
		return 2, usageError{"unknown auth subcommand " + args[0]}
	case "admin":
		const adminUsage = "usage: rabbit admin key set | rm, rabbit admin bindings list | add ... | rm ID, or rabbit admin audit [...]"
		if len(args) == 0 || (args[0] != "audit" && len(args) < 2) {
			return 2, usageError{adminUsage}
		}
		if err := a.selectEnv(envFlag, serverFlag); err != nil {
			return 1, err
		}
		switch args[0] {
		case "audit":
			return a.audit(ctx, args[1:])
		case "key":
			return a.bunnyKey(ctx, args[1], args[2:])
		case "bindings":
			return a.bindings(ctx, args[1], args[2:])
		}
		return 2, usageError{adminUsage}
	case "skill":
		return a.skillCommand(args)
	}
	return 2, usageError{fmt.Sprintf("unknown command %q (BunnyCLI commands go after `--`, e.g. rabbit -- %s)", name, name)}
}

// ---------------------------------------------------------------- agent skill

// skillCommand installs or prints the embedded SKILL.md. Install overwrites, so it always matches this binary.
func (a *App) skillCommand(args []string) (int, error) {
	if len(args) > 0 && args[0] == "print" {
		_, err := a.Stdout.Write(skill.Markdown)
		return 0, err
	}
	if len(args) == 0 || args[0] != "install" {
		return 2, usageError{"usage: rabbit skill install [--dir DIR] | print"}
	}
	fs := flag.NewFlagSet("skill install", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	dir := fs.String("dir", "", "write SKILL.md only to this directory")
	if err := fs.Parse(args[1:]); err != nil {
		return 2, usageError{err.Error()}
	}
	dirs := []string{*dir}
	if *dir == "" {
		home := homeDir(runtime.GOOS, a.Getenv)
		claude := a.Getenv("CLAUDE_CONFIG_DIR")
		if claude == "" && home != "" {
			claude = filepath.Join(home, ".claude")
		}
		agents := "" // the shared Agent Skills folder: Codex, Gemini CLI, GitHub Copilot, OpenCode
		if home != "" {
			agents = filepath.Join(home, ".agents")
		}
		// Only for agents that are in use: their configuration directory exists.
		dirs = nil
		for _, base := range []string{claude, agents} {
			if info, err := os.Stat(base); base != "" && err == nil && info.IsDir() {
				dirs = append(dirs, filepath.Join(base, "skills", "rabbit"))
			}
		}
		if len(dirs) == 0 {
			return 1, errors.New("found neither ~/.claude nor ~/.agents; use --dir for another agent's skill directory")
		}
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return 1, err
		}
		path := filepath.Join(d, "SKILL.md")
		if err := os.WriteFile(path, skill.Markdown, 0o644); err != nil {
			return 1, err
		}
		fmt.Fprintf(a.Stdout, "Installed the rabbit skill at %s.\n", path)
	}
	return 0, nil
}

// homeDir is the directory agents put ~/.claude and ~/.agents in. On Windows that is the user profile, even when
// Git Bash or MSYS sets HOME elsewhere: Claude Code and the other agents use the profile there.
func homeDir(goos string, getenv func(string) string) string {
	first, second := "HOME", "USERPROFILE"
	if goos == "windows" {
		first, second = second, first
	}
	if h := getenv(first); h != "" {
		return h
	}
	return getenv(second)
}

// ---------------------------------------------------------------- environments

func (a *App) configPath() (string, error) { return config.Path(a.Getenv) }

func (a *App) selectEnv(envFlag, serverFlag string) error {
	path, err := a.configPath()
	if err != nil {
		return err
	}
	f, err := config.Load(path)
	if err != nil {
		return err
	}
	a.selected, err = config.Select(f, envFlag, serverFlag, a.Getenv)
	return err
}

func (a *App) envCommand(args []string) (int, error) {
	path, err := a.configPath()
	if err != nil {
		return 1, err
	}
	f, err := config.Load(path)
	if err != nil {
		return 1, err
	}
	if len(args) == 0 || args[0] == "list" {
		if len(f.Environments) == 0 {
			fmt.Fprintln(a.Stdout, "No environments. Add one with: rabbit env add <name> <url>")
		}
		for _, n := range f.Names() {
			marker := "  "
			if n == f.Current {
				marker = "* "
			}
			fmt.Fprintf(a.Stdout, "%s%-12s %s\n", marker, n, f.Environments[n].URL)
		}
		return 0, nil
	}
	switch args[0] {
	case "add":
		if len(args) != 3 {
			return 2, usageError{"usage: rabbit env add <name> <url>"}
		}
		u, err := config.NormalizeURL(args[2])
		if err != nil {
			return 1, err
		}
		f.Environments[args[1]] = config.Environment{URL: u}
		if len(f.Environments) == 1 {
			f.Current = args[1]
		}
	case "use":
		if len(args) != 2 {
			return 2, usageError{"usage: rabbit env use <name>"}
		}
		if _, ok := f.Environments[args[1]]; !ok {
			return 1, fmt.Errorf("unknown environment %q", args[1])
		}
		f.Current = args[1]
	case "remove", "rm":
		if len(args) != 2 {
			return 2, usageError{"usage: rabbit env remove <name>"}
		}
		e, ok := f.Environments[args[1]]
		if !ok {
			return 1, fmt.Errorf("unknown environment %q", args[1])
		}
		if u, err := config.NormalizeURL(e.URL); err == nil {
			_ = a.Secrets.Delete(u)
		}
		delete(f.Environments, args[1])
		if f.Current == args[1] {
			f.Current = ""
		}
	default:
		return 2, usageError{"usage: rabbit env list | add NAME URL | use NAME | remove NAME"}
	}
	if err := f.Save(path); err != nil {
		return 1, err
	}
	return a.envCommand([]string{"list"})
}

// ---------------------------------------------------------------- sessions

func (a *App) client() *api.Client {
	c := api.New(a.selected.URL, "rabbit/"+Version)
	if a.HTTP != nil {
		c.HTTP = a.HTTP
	}
	return c
}

func (a *App) announce() { fmt.Fprintf(a.Stderr, "rabbit: White Rabbit %s\n", a.selected.Label()) }

func (a *App) ciPlatform() (ci.Platform, error) {
	p := ci.Detect(a.Getenv)
	if p == ci.None && ci.Forced(a.Getenv) {
		return ci.None, errors.New("RABBIT_AUTH=ci is set but this is not GitHub Actions or Forgejo Actions")
	}
	return p, nil
}

// session returns a White Rabbit session token: in CI a fresh one from the job's OIDC token, otherwise the stored
// interactive session. It never falls back to anything else.
func (a *App) session(ctx context.Context) (string, error) {
	platform, err := a.ciPlatform()
	if err != nil {
		return "", err
	}
	if platform != ci.None {
		a.ciOnce.Do(func() { a.ciToken, a.ciErr = a.exchangeCI(ctx, platform) })
		return a.ciToken, a.ciErr
	}
	s, err := a.Secrets.Get(a.selected.URL)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		return "", fmt.Errorf("not signed in to %s: run `rabbit auth login`", a.selected.Label())
	case err != nil:
		return "", err
	case s.Expired(time.Now()):
		return "", fmt.Errorf("the session for %s has expired: run `rabbit auth login`", a.selected.Label())
	}
	return s.Token, nil
}

func (a *App) exchangeCI(ctx context.Context, platform ci.Platform) (string, error) {
	cfg, err := a.client().Config(ctx)
	if err != nil {
		return "", err
	}
	token, err := ci.IdentityToken(ctx, platform, cfg.FederationAudience, a.Getenv, a.HTTP)
	if err != nil {
		return "", err
	}
	s, err := a.client().Exchange(ctx, token)
	if err != nil {
		return "", fmt.Errorf("exchanging the %s identity token: %w", platform, err)
	}
	return s.AccessToken, nil
}

// ---------------------------------------------------------------- auth commands

func (a *App) login(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("auth login", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	noBrowser := fs.Bool("no-browser", false, "print the URL instead of opening a browser")
	if err := fs.Parse(args); err != nil {
		return 2, usageError{err.Error()}
	}
	if p, _ := a.ciPlatform(); p != ci.None {
		return 1, errors.New("interactive login is not used in CI: rabbit authenticates with the job's OIDC token automatically")
	}
	a.announce()
	open := a.OpenBrowser
	if *noBrowser {
		open = nil
	}
	code, verifier, err := login.Code(ctx, login.Options{Server: a.selected.URL, OpenBrowser: open, Out: a.Stderr})
	if err != nil {
		return 1, err
	}
	s, err := a.client().ExchangeCode(ctx, code, verifier)
	if err != nil {
		return 1, err
	}
	if err := a.Secrets.Set(a.selected.URL, secrets.Session{Token: s.AccessToken, ExpiresAt: s.ExpiresAt}); err != nil {
		fmt.Fprintf(a.Stderr, "rabbit: warning: %v; the session is not saved and later commands will ask you to sign in again\n", err)
	}
	fmt.Fprintf(a.Stdout, "Signed in to %s as %s until %s.\n", a.selected.Label(), s.Principal.Email, s.ExpiresAt.Local().Format(time.RFC1123))
	if !s.Principal.HasBunnyKey {
		fmt.Fprintln(a.Stdout, "No bunny.net API key is stored yet: run rabbit admin key set.")
	}
	return 0, nil
}

func (a *App) status(ctx context.Context) (int, error) {
	fmt.Fprintf(a.Stdout, "Environment: %s (from %s)\n", a.selected.Label(), a.selected.Source)
	platform, err := a.ciPlatform()
	if err != nil {
		return 1, err
	}
	if platform != ci.None {
		fmt.Fprintf(a.Stdout, "Authentication: %s Actions OIDC token, exchanged per command\n", platform)
		return 0, nil
	}
	s, err := a.Secrets.Get(a.selected.URL)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		fmt.Fprintln(a.Stdout, "Session: not signed in (rabbit auth login)")
		return 1, nil
	case err != nil:
		return 1, err
	case s.Expired(time.Now()):
		fmt.Fprintln(a.Stdout, "Session: expired (rabbit auth login)")
		return 1, nil
	}
	fmt.Fprintf(a.Stdout, "Session: valid until %s\n", s.ExpiresAt.Local().Format(time.RFC1123))
	return 0, nil
}

func (a *App) whoami(ctx context.Context, args []string) (int, error) {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		return 2, usageError{"usage: rabbit auth whoami [--json]"}
	}
	if !asJSON {
		a.announce()
	}
	token, err := a.session(ctx)
	if err != nil {
		return 1, err
	}
	p, err := a.client().WhoAmI(ctx, token)
	if err != nil {
		return 1, err
	}
	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		return 0, enc.Encode(p)
	}
	rows := [][2]string{{"Type", p.Type}}
	if p.Email != "" {
		rows = append(rows, [2]string{"User", p.Email})
	} else {
		rows = append(rows, [2]string{"Owner", p.Owner}, [2]string{"Subject", p.Subject}, [2]string{"Repository", p.Repository},
			[2]string{"Ref", p.Ref}, [2]string{"Workflow", p.WorkflowRef}, [2]string{"Run", p.RunId})
		if p.BindingId != nil {
			rows = append(rows, [2]string{"Binding", strconv.FormatInt(*p.BindingId, 10)})
		}
	}
	bunnyKey := "stored"
	if !p.HasBunnyKey {
		bunnyKey = "not set (rabbit admin key set)"
	}
	rows = append(rows, [2]string{"Issuer", p.Issuer}, [2]string{"Capabilities", strings.Join(p.Capabilities, ", ")},
		[2]string{"Bunny key", bunnyKey},
		[2]string{"Session until", p.SessionExpiresAt.Local().Format(time.RFC1123)})
	for _, r := range rows {
		if r[1] != "" {
			fmt.Fprintf(a.Stdout, "%-14s %s\n", r[0]+":", r[1])
		}
	}
	return 0, nil
}

func (a *App) logout(ctx context.Context) (int, error) {
	a.announce()
	s, err := a.Secrets.Get(a.selected.URL)
	if errors.Is(err, secrets.ErrNotFound) {
		fmt.Fprintln(a.Stdout, "Not signed in.")
		return 0, nil
	}
	if err != nil {
		return 1, err
	}
	revokeErr := a.client().Revoke(ctx, s.Token)
	if err := a.Secrets.Delete(a.selected.URL); err != nil {
		return 1, err
	}
	if revokeErr != nil && !api.IsStatus(revokeErr, http.StatusUnauthorized) {
		fmt.Fprintf(a.Stderr, "rabbit: the local session was removed, but revoking it on the server failed: %v\n", revokeErr)
		return 1, nil
	}
	fmt.Fprintln(a.Stdout, "Signed out.")
	return 0, nil
}

// ---------------------------------------------------------------- admin key

// bunnyKey stores or removes the owner's bunny.net API key. The key is read from stdin, without echo on a terminal,
// so it never appears in argv, shell history or the process list.
func (a *App) bunnyKey(ctx context.Context, sub string, args []string) (int, error) {
	if len(args) > 0 || (sub != "set" && sub != "rm" && sub != "remove") {
		return 2, usageError{"usage: rabbit admin key set | rm (set reads the key from stdin)"}
	}
	if p, _ := a.ciPlatform(); p != ci.None {
		return 1, errors.New("the bunny.net API key can only be managed from an interactive session, not from CI")
	}
	a.announce()
	token, err := a.session(ctx)
	if err != nil {
		return 1, err
	}
	if sub != "set" {
		if err := a.client().RemoveBunnyKey(ctx, token); err != nil {
			return 1, err
		}
		fmt.Fprintln(a.Stdout, "Removed the bunny.net API key.")
		return 0, nil
	}
	key, err := a.readSecret("bunny.net API key: ")
	if err != nil {
		return 1, err
	}
	if key == "" {
		return 2, usageError{"no key given: type it at the prompt or pipe it in, e.g. rabbit admin key set < key.txt"}
	}
	if err := a.client().SetBunnyKey(ctx, token, key); err != nil {
		return 1, err
	}
	fmt.Fprintln(a.Stdout, "Stored the bunny.net API key.")
	return 0, nil
}

// readSecret prompts without echo when stdin is a terminal, and otherwise reads the first line of stdin.
func (a *App) readSecret(prompt string) (string, error) {
	if f, ok := a.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(a.Stderr, prompt)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(a.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	line, err := bufio.NewReader(io.LimitReader(a.Stdin, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// ---------------------------------------------------------------- admin audit

func (a *App) audit(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("admin audit", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	since := fs.String("since", "24h", "how far back, e.g. 30m, 24h or 7d")
	binding := fs.Int64("binding", 0, "only this binding's events")
	limit := fs.Int("limit", 50, "at most this many events (1-500), the newest")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2, usageError{err.Error()}
	}
	back, err := parseAge(*since)
	if err != nil {
		return 2, usageError{err.Error()}
	}
	if p, _ := a.ciPlatform(); p != ci.None {
		return 1, errors.New("the audit log can only be read from an interactive session, not from CI")
	}
	if !*asJSON {
		a.announce()
	}
	token, err := a.session(ctx)
	if err != nil {
		return 1, err
	}
	events, err := a.client().Audit(ctx, token, time.Now().Add(-back), *binding, *limit)
	if err != nil {
		return 1, err
	}
	if *asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		return 0, enc.Encode(events)
	}
	if len(events) == 0 {
		fmt.Fprintln(a.Stdout, "No events.")
	}
	// Oldest first, like a log; the server returns the newest first.
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		line := fmt.Sprintf("%s  %-7s %-22s", e.OccurredUtc.Local().Format("2006-01-02 15:04:05"), e.Outcome, e.EventType)
		for _, part := range []string{e.Reason, who(e), e.OperationId, status(e)} {
			if part != "" {
				line += "  " + part
			}
		}
		fmt.Fprintln(a.Stdout, line)
	}
	return 0, nil
}

// parseAge accepts Go durations plus whole days ("7d").
func parseAge(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--since must be a duration such as 30m, 24h or 7d, not %q", s)
	}
	return d, nil
}

func who(e api.AuditEvent) string {
	switch {
	case e.Repository != "" && e.BindingId != nil:
		return fmt.Sprintf("%s #%d", e.Repository, *e.BindingId)
	case e.Repository != "":
		return e.Repository
	default:
		return e.PrincipalType
	}
}

func status(e api.AuditEvent) string {
	switch {
	case e.HttpStatus == nil:
		return ""
	case e.UpstreamStatus != nil && *e.UpstreamStatus != *e.HttpStatus:
		return fmt.Sprintf("%d (bunny %d)", *e.HttpStatus, *e.UpstreamStatus)
	default:
		return strconv.Itoa(*e.HttpStatus)
	}
}

// ---------------------------------------------------------------- admin bindings

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func (a *App) bindings(ctx context.Context, sub string, args []string) (int, error) {
	if p, _ := a.ciPlatform(); p != ci.None {
		return 1, errors.New("bindings can only be managed from an interactive session, not from CI")
	}
	a.announce()
	token, err := a.session(ctx)
	if err != nil {
		return 1, err
	}
	client := a.client()
	switch sub {
	case "list", "ls":
		list, err := client.ListBindings(ctx, token)
		if err != nil {
			return 1, err
		}
		if len(list) == 0 {
			fmt.Fprintln(a.Stdout, "No workload bindings.")
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Id < list[j].Id })
		for _, b := range list {
			ref := b.Ref
			if ref == "" {
				ref = "(any ref)"
			}
			fmt.Fprintf(a.Stdout, "#%d %s %s %s\n    workflow: %s\n    events: %s  capabilities: %s\n", b.Id, b.Issuer, b.Repository, ref,
				b.WorkflowRef, strings.Join(b.Events, ","), strings.Join(b.Capabilities, ","))
			if b.Environment != "" {
				fmt.Fprintf(a.Stdout, "    environment: %s\n", b.Environment)
			}
		}
		return 0, nil
	case "add":
		fs := flag.NewFlagSet("admin bindings add", flag.ContinueOnError)
		fs.SetOutput(a.Stderr)
		var b api.Binding
		var events, caps multi
		var workflow string
		fs.StringVar(&b.Issuer, "issuer", "", "trusted issuer name, e.g. github or codebahn (required)")
		fs.StringVar(&b.Repository, "repository", "", "owner/name (required)")
		fs.StringVar(&b.RepositoryId, "repository-id", "", "GitHub numeric repository ID (required for GitHub)")
		fs.StringVar(&b.RepositoryOwnerId, "repository-owner-id", "", "GitHub numeric owner ID (optional)")
		fs.StringVar(&b.Ref, "ref", "", "exact ref, e.g. refs/heads/main (optional: without it any branch or tag matches)")
		fs.StringVar(&workflow, "workflow", "", "workflow file path, e.g. .github/workflows/deploy.yml (or use --workflow-ref)")
		fs.StringVar(&b.WorkflowRef, "workflow-ref", "", "exact workflow_ref: <repository>/<path>@<ref>, or <repository>/<path> without --ref")
		fs.StringVar(&b.JobWorkflowRef, "job-workflow-ref", "", "GitHub reusable workflow job_workflow_ref (optional)")
		fs.StringVar(&b.Environment, "environment", "", "GitHub deployment environment (optional)")
		fs.Var(&events, "event", "allowed event, repeatable (default: push and workflow_dispatch)")
		fs.Var(&caps, "capability", "capability to grant, repeatable")
		fs.StringVar(&b.Description, "description", "", "free text")
		if err := fs.Parse(args); err != nil {
			return 2, usageError{err.Error()}
		}
		if b.WorkflowRef == "" && workflow != "" {
			b.WorkflowRef = b.Repository + "/" + strings.TrimPrefix(workflow, "/")
			if b.Ref != "" {
				b.WorkflowRef += "@" + b.Ref
			}
		}
		b.Events, b.Capabilities = events, caps
		created, err := client.CreateBinding(ctx, token, b)
		if err != nil {
			return 1, err
		}
		ref := created.Ref
		if ref == "" {
			ref = "(any ref)"
		}
		fmt.Fprintf(a.Stdout, "Created binding #%d for %s %s (%s).\n", created.Id, created.Repository, ref, created.WorkflowRef)
		return 0, nil
	case "rm", "remove", "revoke":
		if len(args) != 1 {
			return 2, usageError{"usage: rabbit admin bindings rm ID"}
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(args[0], "#"), 10, 64)
		if err != nil {
			return 2, usageError{"binding ID must be a number"}
		}
		if err := client.DeleteBinding(ctx, token, id); err != nil {
			return 1, err
		}
		fmt.Fprintf(a.Stdout, "Revoked binding #%d.\n", id)
		return 0, nil
	}
	return 2, usageError{"usage: rabbit admin bindings list | add ... | rm ID"}
}

// ---------------------------------------------------------------- passthrough

func (a *App) passthrough(ctx context.Context, envFlag, serverFlag string, args []string) (int, error) {
	if err := passthrough.CheckArgs(args); err != nil {
		return 2, err
	}
	bunny, err := passthrough.ResolveBunny(a.Getenv, a.Self)
	if err != nil {
		return 1, err
	}
	if err := a.selectEnv(envFlag, serverFlag); err != nil {
		return 1, err
	}
	if a.StderrIsTTY {
		a.announce()
	}
	var debug io.Writer
	if a.Getenv("RABBIT_DEBUG") != "" {
		debug = a.Stderr
	}
	credentials := func(ctx context.Context) (string, time.Time, error) {
		token, err := a.session(ctx)
		if err != nil {
			return "", time.Time{}, err
		}
		// --capabilities or RABBIT_CAPABILITIES narrows the virtual credential, e.g. for an AI agent; the session
		// itself has all.
		list := a.capabilities
		if list == "" {
			list = a.Getenv("RABBIT_CAPABILITIES")
		}
		var capabilities []string
		for _, c := range strings.Split(list, ",") {
			if c = strings.TrimSpace(c); c != "" {
				capabilities = append(capabilities, c)
			}
		}
		c, err := a.client().Credential(ctx, token, capabilities)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("getting a credential from White Rabbit: %w", err)
		}
		return c.AccessKey, c.ExpiresAt, nil
	}
	var transport http.RoundTripper
	if a.HTTP != nil {
		transport = a.HTTP.Transport
	}
	return passthrough.Run(ctx, passthrough.Options{
		Server: a.selected.URL, Credentials: credentials, BunnyPath: bunny, Args: args, Environ: a.Environ,
		Stdin: a.Stdin, Stdout: a.Stdout, Stderr: a.Stderr, Debug: debug, Transport: transport,
	})
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

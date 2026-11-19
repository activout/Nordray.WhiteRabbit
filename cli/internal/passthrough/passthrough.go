// Package passthrough runs the official BunnyCLI as `rabbit -- <arguments>` against White Rabbit instead of
// api.bunny.net. The child never sees a real Bunny key or a White Rabbit credential: it talks to a loopback
// forwarder in this process with a one-time local key.
package passthrough

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
)

// Options for one run.
type Options struct {
	Server      string // White Rabbit origin
	Credentials CredentialSource
	BunnyPath   string // resolved with ResolveBunny
	Args        []string
	Environ     []string // the parent environment
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Debug       io.Writer // forwarder log lines, nil for none
	Transport   http.RoundTripper
}

// ResolveBunny finds the BunnyCLI executable: $RABBIT_BUNNY, else `bunny` on PATH. Nothing is downloaded.
func ResolveBunny(getenv func(string) string, self string) (string, error) {
	path := getenv("RABBIT_BUNNY")
	if path == "" {
		found, err := exec.LookPath("bunny")
		if err != nil {
			return "", errors.New("BunnyCLI (`bunny`) was not found on PATH. Install it (https://github.com/BunnyWay/cli), or set RABBIT_BUNNY to its path")
		}
		path = found
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(abs); err != nil || info.IsDir() {
		return "", fmt.Errorf("BunnyCLI not found at %s", abs)
	}
	if self != "" && sameFile(abs, self) {
		return "", errors.New("RABBIT_BUNNY points at rabbit itself")
	}
	return abs, nil
}

// CheckArgs refuses arguments that would hand BunnyCLI a real key.
func CheckArgs(args []string) error {
	for _, a := range args {
		if a == "--api-key" || strings.HasPrefix(a, "--api-key=") {
			return errors.New("rabbit does not pass --api-key to BunnyCLI: White Rabbit supplies the credential. Remove --api-key")
		}
	}
	return nil
}

// ChildEnv is the parent environment without any Bunny or CI credential, plus the forwarder's address and key.
func ChildEnv(parent []string, apiURL, localKey string) []string {
	out := make([]string, 0, len(parent)+5)
	noProxy := ""
	for _, kv := range parent {
		name, value, _ := strings.Cut(kv, "=")
		upper := strings.ToUpper(name)
		switch {
		case strings.HasPrefix(upper, "BUNNYNET_"), strings.HasPrefix(upper, "BUNNY_"),
			strings.HasPrefix(upper, "ACTIONS_ID_TOKEN_REQUEST_"), strings.HasPrefix(upper, "ACTIONS_RUNTIME_"),
			upper == "GITHUB_TOKEN", upper == "FORGEJO_TOKEN", upper == "GITEA_TOKEN", strings.HasPrefix(upper, "RABBIT_"):
			continue
		case upper == "NO_PROXY":
			if value != "" {
				noProxy = value
			}
			continue
		}
		out = append(out, kv)
	}
	// BunnyCLI honours HTTP(S)_PROXY even for 127.0.0.1; the local key must never go through a proxy.
	loopback := "127.0.0.1,localhost,::1"
	if noProxy != "" {
		loopback = noProxy + "," + loopback
	}
	return append(out,
		"BUNNYNET_API_URL="+apiURL,
		"BUNNYNET_API_KEY="+localKey,
		// `bunny login` opens this; point it nowhere rather than at the real dashboard.
		"BUNNYNET_DASHBOARD_URL=http://127.0.0.1:1",
		"NO_PROXY="+loopback,
		"no_proxy="+loopback,
	)
}

// Run starts the forwarder and the child, waits, and returns the child's exit code.
func Run(ctx context.Context, o Options) (int, error) {
	if err := CheckArgs(o.Args); err != nil {
		return 2, err
	}
	forwarder, err := StartForwarder(o.Server, o.Credentials, o.Transport, o.Debug)
	if err != nil {
		return 1, err
	}
	defer forwarder.Close()

	// Fail before starting BunnyCLI if no credential can be obtained, rather than letting it see 401s.
	if _, err := forwarder.credential(ctx); err != nil {
		return 1, err
	}

	cmd := exec.Command(o.BunnyPath, o.Args...)
	cmd.Env = ChildEnv(o.Environ, forwarder.URL, forwarder.LocalKey)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = o.Stdin, o.Stdout, o.Stderr
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("starting BunnyCLI: %w", err)
	}

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, forwardedSignals()...)
	defer signal.Stop(signals)
	go func() {
		for s := range signals {
			// The terminal already sends Ctrl-C to the child's process group; forwarding covers kill and CI cancellation.
			if runtime.GOOS != "windows" {
				_ = cmd.Process.Signal(s)
			}
		}
	}()

	err = cmd.Wait()
	close(signals)
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exitCode(exit), nil
	}
	return 1, err
}

func sameFile(a, b string) bool {
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ia, ib)
}

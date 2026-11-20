// Package login runs the interactive sign-in: the system browser signs in to White Rabbit's /cli/login, which sends
// a one-time code to a loopback listener on 127.0.0.1. The code is bound to this process's PKCE S256 challenge, so
// only the verifier held here can redeem it at /api/cli/exchange. No secret is shipped in the binary.
package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Options configures one sign-in.
type Options struct {
	Server      string // normalised origin of the White Rabbit server
	OpenBrowser func(url string) error
	Out         io.Writer // where the URL is printed if the browser cannot be opened
	Timeout     time.Duration
}

// Code signs in and returns the one-time code and its PKCE verifier, which the caller exchanges at once.
func Code(ctx context.Context, o Options) (code, verifier string, err error) {
	verifier, challenge := pkce()
	state := random(24)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", fmt.Errorf("cannot listen on 127.0.0.1 for the sign-in redirect: %w", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	q := url.Values{"port": {strconv.Itoa(port)}, "state": {state}, "code_challenge": {challenge}}
	loginURL := o.Server + "/cli/login?" + q.Encode()

	type result struct {
		code string
		err  error
	}
	results := make(chan result, 1)
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			v := r.URL.Query()
			var res result
			switch {
			case v.Get("state") != state:
				res.err = errors.New("sign-in failed: the redirect's state did not match (possible cross-site request)")
			case v.Get("code") == "":
				res.err = errors.New("sign-in failed: no code in the redirect")
			default:
				res.code = v.Get("code")
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			message := "Signed in. You can close this window and return to the terminal."
			if res.err != nil {
				message = res.err.Error()
			}
			fmt.Fprintf(w, "<!doctype html><title>rabbit</title><p>%s</p>", html.EscapeString(message))
			select {
			case results <- res:
			default:
			}
		}),
	}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	if o.OpenBrowser == nil || o.OpenBrowser(loginURL) != nil {
		fmt.Fprintf(o.Out, "Open this URL in a browser on this computer to sign in:\n\n  %s\n\n", loginURL)
	} else {
		fmt.Fprintf(o.Out, "Opening the browser to sign in. If it does not open, visit:\n\n  %s\n\n", loginURL)
	}

	timeout := o.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	select {
	case res := <-results:
		return res.code, verifier, res.err
	case <-time.After(timeout):
		return "", "", errors.New("sign-in timed out")
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
}

func pkce() (verifier, challenge string) {
	verifier = random(32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

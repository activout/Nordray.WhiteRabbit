package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeServer plays White Rabbit's /cli/login: it checks the parameters and redirects to the loopback callback.
type fakeServer struct {
	challenge  string
	tamperWith func(callback url.URL) url.URL
}

// browser opens the login URL as a real browser would: it follows /cli/login's redirect to the loopback callback.
func (f *fakeServer) browser(t *testing.T) func(string) error {
	return func(loginURL string) error {
		u, err := url.Parse(loginURL)
		if err != nil || u.Path != "/cli/login" {
			t.Errorf("unexpected login URL %q", loginURL)
			return nil
		}
		q := u.Query()
		f.challenge = q.Get("code_challenge")
		callback := url.URL{Scheme: "http", Host: "127.0.0.1:" + q.Get("port"), Path: "/callback",
			RawQuery: url.Values{"code": {"wrc_the-code"}, "state": {q.Get("state")}}.Encode()}
		if f.tamperWith != nil {
			callback = f.tamperWith(callback)
		}
		go func() {
			if resp, err := http.Get(callback.String()); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

func (f *fakeServer) options(t *testing.T) Options {
	return Options{Server: "https://rabbit.example", OpenBrowser: f.browser(t), Out: io.Discard, Timeout: 5 * time.Second}
}

func TestLoginReturnsCodeAndMatchingVerifier(t *testing.T) {
	f := &fakeServer{}
	code, verifier, err := Code(context.Background(), f.options(t))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if code != "wrc_the-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
		t.Fatalf("code %q, verifier does not match the challenge", code)
	}
}

func TestLoginRejectsStateMismatch(t *testing.T) {
	f := &fakeServer{tamperWith: func(u url.URL) url.URL {
		v := u.Query()
		v.Set("state", "attacker")
		u.RawQuery = v.Encode()
		return u
	}}
	if _, _, err := Code(context.Background(), f.options(t)); err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginRejectsMissingCode(t *testing.T) {
	f := &fakeServer{tamperWith: func(u url.URL) url.URL {
		v := u.Query()
		v.Del("code")
		u.RawQuery = v.Encode()
		return u
	}}
	if _, _, err := Code(context.Background(), f.options(t)); err == nil || !strings.Contains(err.Error(), "no code") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginPrintsTheURLWithoutABrowser(t *testing.T) {
	var out strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, _ = Code(ctx, Options{Server: "https://rabbit.example", Out: &out})
	if !strings.Contains(out.String(), "https://rabbit.example/cli/login?") {
		t.Fatalf("URL not printed: %q", out.String())
	}
}

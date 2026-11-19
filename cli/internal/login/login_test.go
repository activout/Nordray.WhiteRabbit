package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/activout/nordray.whiterabbit/cli/internal/api"
)

// fakeDex is an authorization server that checks PKCE S256 like Dex does.
type fakeDex struct {
	server     *httptest.Server
	challenge  string
	nonce      string
	tamperWith func(redirect url.URL) url.URL
	badNonce   bool
}

func newFakeDex(t *testing.T) *fakeDex {
	d := &fakeDex{}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != "rabbit-cli" || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !strings.Contains(q.Get("scope"), "statistics.read") {
			http.Error(w, "capabilities missing from scope", http.StatusBadRequest)
			return
		}
		d.challenge, d.nonce = q.Get("code_challenge"), q.Get("nonce")
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		v := redirect.Query()
		v.Set("code", "the-code")
		v.Set("state", q.Get("state"))
		redirect.RawQuery = v.Encode()
		if d.tamperWith != nil {
			*redirect = d.tamperWith(*redirect)
		}
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("code") != "the-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != d.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		nonce := d.nonce
		if d.badNonce {
			nonce = "someone-elses-nonce"
		}
		payload, _ := json.Marshal(map[string]string{"nonce": nonce, "email": "me@example.com"})
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"})
	})
	d.server = httptest.NewServer(mux)
	t.Cleanup(d.server.Close)
	return d
}

func (d *fakeDex) discovery() *api.DiscoveryDocument {
	return &api.DiscoveryDocument{Issuer: d.server.URL, AuthorizationEndpoint: d.server.URL + "/auth", TokenEndpoint: d.server.URL + "/token"}
}

// browser follows the authorization redirect to the loopback callback, as a real browser would.
func browser(t *testing.T) func(string) error {
	return func(authURL string) error {
		go func() {
			resp, err := http.Get(authURL)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

func options(d *fakeDex, t *testing.T) Options {
	return Options{
		Server: d.server.URL, ClientId: "rabbit-cli", Capabilities: []string{"statistics.read"},
		OpenBrowser: browser(t), Out: io.Discard, Timeout: 5 * time.Second,
	}
}

func TestLoginWithPkce(t *testing.T) {
	d := newFakeDex(t)
	token, err := IDToken(context.Background(), d.discovery(), options(d, t))
	if err != nil {
		t.Fatal(err)
	}
	if unverifiedClaim(token, "email") != "me@example.com" {
		t.Fatalf("unexpected token %q", token)
	}
}

func TestLoginRejectsStateMismatch(t *testing.T) {
	d := newFakeDex(t)
	d.tamperWith = func(u url.URL) url.URL {
		v := u.Query()
		v.Set("state", "attacker")
		u.RawQuery = v.Encode()
		return u
	}
	if _, err := IDToken(context.Background(), d.discovery(), options(d, t)); err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginRejectsNonceMismatch(t *testing.T) {
	d := newFakeDex(t)
	d.badNonce = true
	if _, err := IDToken(context.Background(), d.discovery(), options(d, t)); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginRefusesForeignEndpoints(t *testing.T) {
	d := newFakeDex(t)
	for _, doc := range []*api.DiscoveryDocument{
		{Issuer: "https://evil.example", AuthorizationEndpoint: d.server.URL + "/auth", TokenEndpoint: d.server.URL + "/token"},
		{Issuer: d.server.URL, AuthorizationEndpoint: "https://evil.example/auth", TokenEndpoint: d.server.URL + "/token"},
		{Issuer: d.server.URL, AuthorizationEndpoint: d.server.URL + "/auth", TokenEndpoint: "https://evil.example/token"},
	} {
		if _, err := IDToken(context.Background(), doc, options(d, t)); err == nil {
			t.Errorf("discovery %+v accepted", doc)
		}
	}
}

func TestLoginReportsDenial(t *testing.T) {
	d := newFakeDex(t)
	d.tamperWith = func(u url.URL) url.URL {
		v := u.Query()
		v.Del("code")
		v.Set("error", "access_denied")
		u.RawQuery = v.Encode()
		return u
	}
	if _, err := IDToken(context.Background(), d.discovery(), options(d, t)); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("got %v", err)
	}
}

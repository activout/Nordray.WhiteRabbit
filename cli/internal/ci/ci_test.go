package ci

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDetect(t *testing.T) {
	cases := []struct {
		vars map[string]string
		want Platform
	}{
		{nil, None},
		{map[string]string{"GITHUB_ACTIONS": "true"}, GitHub},
		// Forgejo also sets GitHub compatibility variables.
		{map[string]string{"GITHUB_ACTIONS": "true", "FORGEJO_ACTIONS": "true"}, Forgejo},
		{map[string]string{"GITEA_ACTIONS": "true"}, Forgejo},
		{map[string]string{"GITHUB_ACTIONS": "true", "RABBIT_AUTH": "interactive"}, None},
	}
	for _, c := range cases {
		if got := Detect(env(c.vars)); got != c.want {
			t.Errorf("Detect(%v) = %q, want %q", c.vars, got, c.want)
		}
	}
}

func TestIdentityToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer request-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("audience") != "whiterabbit:test" || r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"value":"the.id.token"}`))
	}))
	defer server.Close()

	vars := map[string]string{
		// GitHub's URL already carries a query string; the audience must be added to it.
		"ACTIONS_ID_TOKEN_REQUEST_URL":   server.URL + "/idtoken?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token",
	}
	token, err := IdentityToken(context.Background(), GitHub, "whiterabbit:test", env(vars), server.Client())
	if err != nil || token != "the.id.token" {
		t.Fatalf("got %q, %v", token, err)
	}

	var noAccess ErrNoTokenAccess
	if _, err := IdentityToken(context.Background(), Forgejo, "whiterabbit:test", env(nil), nil); !errors.As(err, &noAccess) {
		t.Fatalf("missing request variables must explain enable-openid-connect, got %v", err)
	}
	if _, err := IdentityToken(context.Background(), GitHub, "", env(vars), server.Client()); err == nil {
		t.Fatal("an empty audience must fail")
	}
	vars["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "wrong"
	if _, err := IdentityToken(context.Background(), GitHub, "whiterabbit:test", env(vars), server.Client()); err == nil {
		t.Fatal("a refused token request must fail")
	}
}

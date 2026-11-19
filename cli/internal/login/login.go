// Package login runs the interactive sign-in: OIDC authorization code flow with PKCE (S256), the system browser
// and a loopback redirect on 127.0.0.1. The rabbit CLI is a public client, so no secret is shipped in the binary.
package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/activout/nordray.whiterabbit/cli/internal/api"
)

// Options configures one sign-in.
type Options struct {
	Server       string // normalised origin; the issuer and every endpoint must be on it
	ClientId     string
	Capabilities []string // requested as scopes, approved on White Rabbit's consent page
	OpenBrowser  func(url string) error
	Out          io.Writer // where the URL is printed if the browser cannot be opened
	Timeout      time.Duration
	HTTP         *http.Client
}

// IDToken signs in and returns Dex's ID token, which the caller exchanges for a White Rabbit session at once.
func IDToken(ctx context.Context, discovery *api.DiscoveryDocument, o Options) (string, error) {
	if err := checkSameOrigin(o.Server, discovery); err != nil {
		return "", err
	}
	verifier, challenge := pkce()
	state, nonce := random(24), random(24)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("cannot listen on 127.0.0.1 for the sign-in redirect: %w", err)
	}
	defer listener.Close()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)

	scopes := append([]string{"openid", "email", "profile"}, o.Capabilities...)
	q := url.Values{
		"client_id":             {o.ClientId},
		"response_type":         {"code"},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authURL := discovery.AuthorizationEndpoint + "?" + q.Encode()

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
			case v.Get("error") != "":
				res.err = fmt.Errorf("sign-in was not completed: %s", v.Get("error"))
			case v.Get("code") == "":
				res.err = errors.New("sign-in failed: no authorization code in the redirect")
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

	if o.OpenBrowser == nil || o.OpenBrowser(authURL) != nil {
		fmt.Fprintf(o.Out, "Open this URL in a browser on this computer to sign in:\n\n  %s\n\n", authURL)
	} else {
		fmt.Fprintf(o.Out, "Opening the browser to sign in. If it does not open, visit:\n\n  %s\n\n", authURL)
	}

	timeout := o.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	var res result
	select {
	case res = <-results:
	case <-time.After(timeout):
		return "", errors.New("sign-in timed out")
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if res.err != nil {
		return "", res.err
	}

	idToken, err := redeem(ctx, o.HTTP, discovery.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {res.code},
		"redirect_uri":  {redirect},
		"client_id":     {o.ClientId},
		"code_verifier": {verifier},
	})
	if err != nil {
		return "", err
	}
	if got := unverifiedClaim(idToken, "nonce"); got != nonce {
		return "", errors.New("sign-in failed: the ID token's nonce did not match")
	}
	return idToken, nil
}

func redeem(ctx context.Context, client *http.Client, endpoint string, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("redeeming the authorization code: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var body struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(data, &body)
	if resp.StatusCode != http.StatusOK || body.IDToken == "" {
		if body.Error != "" {
			return "", fmt.Errorf("redeeming the authorization code failed: %s", body.Error)
		}
		return "", fmt.Errorf("redeeming the authorization code failed: HTTP %d", resp.StatusCode)
	}
	return body.IDToken, nil
}

// checkSameOrigin refuses discovery metadata that points anywhere but the configured White Rabbit server, so the
// browser, the authorization code and the verifier never go to another host.
func checkSameOrigin(server string, d *api.DiscoveryDocument) error {
	if strings.TrimSuffix(d.Issuer, "/") != server {
		return fmt.Errorf("the server's OIDC issuer is %q, not %q: refusing to sign in", d.Issuer, server)
	}
	for _, endpoint := range []string{d.AuthorizationEndpoint, d.TokenEndpoint} {
		u, err := url.Parse(endpoint)
		if err != nil || strings.ToLower(u.Scheme+"://"+u.Host) != server {
			return fmt.Errorf("the server's OIDC endpoint %q is not on %s: refusing to sign in", endpoint, server)
		}
	}
	return nil
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

// unverifiedClaim reads one string claim without verifying the signature; White Rabbit verifies the token itself
// when it is exchanged. Used only to check the nonce this process generated.
func unverifiedClaim(jwt, name string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	s, _ := claims[name].(string)
	return s
}

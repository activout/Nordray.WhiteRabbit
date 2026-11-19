// Package ci obtains a CI job's own OIDC identity token from GitHub Actions or Forgejo Actions.
// Both use the ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN interface; the audience is the White Rabbit environment's.
package ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Platform is the detected CI system.
type Platform string

const (
	None    Platform = ""
	GitHub  Platform = "github"
	Forgejo Platform = "forgejo"
)

// Detect works out the CI platform from the environment. Forgejo also sets GITHUB_* compatibility variables,
// so it is recognised first. RABBIT_AUTH=interactive forces the stored interactive session even in CI.
func Detect(getenv func(string) string) Platform {
	switch strings.ToLower(getenv("RABBIT_AUTH")) {
	case "interactive":
		return None
	}
	if getenv("FORGEJO_ACTIONS") == "true" || getenv("GITEA_ACTIONS") == "true" {
		return Forgejo
	}
	if getenv("GITHUB_ACTIONS") == "true" {
		return GitHub
	}
	return None
}

// Forced reports whether RABBIT_AUTH=ci demands CI authentication.
func Forced(getenv func(string) string) bool { return strings.EqualFold(getenv("RABBIT_AUTH"), "ci") }

// ErrNoTokenAccess explains how to give the job an identity token.
type ErrNoTokenAccess struct{ Platform Platform }

func (e ErrNoTokenAccess) Error() string {
	switch e.Platform {
	case Forgejo:
		return "this Forgejo job cannot request an OIDC token: add `enable-openid-connect: true` to the job (permissions: id-token has no effect on Forgejo)"
	case GitHub:
		return "this GitHub Actions job cannot request an OIDC token: add `permissions: id-token: write` to the workflow or job"
	default:
		return "not running in GitHub Actions or Forgejo Actions"
	}
}

// IdentityToken requests an identity token for the audience. The token is returned, never printed.
func IdentityToken(ctx context.Context, platform Platform, audience string, getenv func(string) string, client *http.Client) (string, error) {
	requestURL, requestToken := getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return "", ErrNoTokenAccess{Platform: platform}
	}
	if audience == "" {
		return "", errors.New("the White Rabbit server has no CI federation configured (empty audience)")
	}
	u, err := url.Parse(requestURL)
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && isLocal(u.Hostname()))) {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not an https URL")
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+requestToken)
	req.Header.Set("Accept", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting the CI identity token: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("requesting the CI identity token: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(data, &body) != nil || body.Value == "" {
		return "", errors.New("the CI identity token response had no value")
	}
	return body.Value, nil
}

func isLocal(host string) bool { return host == "127.0.0.1" || host == "localhost" || host == "::1" }

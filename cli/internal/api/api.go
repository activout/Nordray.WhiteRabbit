// Package api is the client for White Rabbit's CLI endpoints. It never logs request or response bodies, which
// carry session tokens and virtual credentials.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to one White Rabbit server.
type Client struct {
	Server    string // normalised origin
	HTTP      *http.Client
	UserAgent string
}

// New returns a client with sane timeouts that does not follow redirects to other hosts.
func New(server, userAgent string) *Client {
	return &Client{
		Server:    server,
		UserAgent: userAgent,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			// A redirect could carry the Authorization header elsewhere; White Rabbit's API never redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Error is a non-success answer from White Rabbit.
type Error struct {
	Status int
	Code   string `json:"error"`
	Reason string `json:"reason"`
}

func (e *Error) Error() string {
	switch {
	case e.Reason != "":
		return fmt.Sprintf("White Rabbit refused the request (%d %s: %s)", e.Status, e.Code, e.Reason)
	case e.Code != "":
		return fmt.Sprintf("White Rabbit refused the request (%d %s)", e.Status, e.Code)
	default:
		return fmt.Sprintf("White Rabbit refused the request (%d)", e.Status)
	}
}

// IsStatus reports whether err is a White Rabbit answer with the given HTTP status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// Config is GET /api/cli/config.
type Config struct {
	DexClientId        string       `json:"dex_client_id"`
	FederationAudience string       `json:"federation_audience"`
	Capabilities       []Capability `json:"capabilities"`
}

type Capability struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Principal is who a session belongs to.
type Principal struct {
	Type             string    `json:"type"`
	Subject          string    `json:"subject"`
	Email            string    `json:"email,omitempty"`
	Owner            string    `json:"owner"`
	Issuer           string    `json:"issuer"`
	ClientId         string    `json:"client_id,omitempty"`
	BindingId        *int64    `json:"binding_id,omitempty"`
	Repository       string    `json:"repository,omitempty"`
	RepositoryId     string    `json:"repository_id,omitempty"`
	Ref              string    `json:"ref,omitempty"`
	WorkflowRef      string    `json:"workflow_ref,omitempty"`
	RunId            string    `json:"run_id,omitempty"`
	Capabilities     []string  `json:"capabilities"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
}

// Session is POST /api/cli/exchange.
type Session struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Principal   Principal `json:"principal"`
}

// Credential is POST /api/cli/credentials.
type Credential struct {
	AccessKey    string    `json:"access_key"`
	CredentialId string    `json:"credential_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Capabilities []string  `json:"capabilities"`
}

// Binding is a workload binding.
type Binding struct {
	Id                int64     `json:"id,omitempty"`
	Issuer            string    `json:"issuer"`
	Repository        string    `json:"repository"`
	RepositoryId      string    `json:"repository_id,omitempty"`
	RepositoryOwnerId string    `json:"repository_owner_id,omitempty"`
	Ref               string    `json:"ref"`
	WorkflowRef       string    `json:"workflow_ref"`
	JobWorkflowRef    string    `json:"job_workflow_ref,omitempty"`
	Environment       string    `json:"environment,omitempty"`
	Events            []string  `json:"events,omitempty"`
	Capabilities      []string  `json:"capabilities"`
	Description       string    `json:"description,omitempty"`
	CreatedUtc        time.Time `json:"created_utc,omitempty"`
}

func (c *Client) Config(ctx context.Context) (*Config, error) {
	var out Config
	return &out, c.do(ctx, http.MethodGet, "/api/cli/config", "", nil, &out)
}

func (c *Client) Exchange(ctx context.Context, subjectToken string) (*Session, error) {
	var out Session
	err := c.do(ctx, http.MethodPost, "/api/cli/exchange", "", map[string]string{"subject_token": subjectToken}, &out)
	return &out, err
}

func (c *Client) Credential(ctx context.Context, session string, capabilities []string) (*Credential, error) {
	var body any
	if len(capabilities) > 0 {
		body = map[string][]string{"capabilities": capabilities}
	}
	var out Credential
	return &out, c.do(ctx, http.MethodPost, "/api/cli/credentials", session, body, &out)
}

func (c *Client) WhoAmI(ctx context.Context, session string) (*Principal, error) {
	var out Principal
	return &out, c.do(ctx, http.MethodGet, "/api/cli/whoami", session, nil, &out)
}

func (c *Client) Revoke(ctx context.Context, session string) error {
	return c.do(ctx, http.MethodPost, "/api/cli/revoke", session, nil, nil)
}

func (c *Client) ListBindings(ctx context.Context, session string) ([]Binding, error) {
	var out []Binding
	return out, c.do(ctx, http.MethodGet, "/api/admin/bindings", session, nil, &out)
}

// BindingProblems is the server's list of reasons a binding was rejected.
type BindingProblems struct {
	Problems []string `json:"problems"`
}

func (c *Client) CreateBinding(ctx context.Context, session string, b Binding) (*Binding, error) {
	var out Binding
	return &out, c.do(ctx, http.MethodPost, "/api/admin/bindings", session, b, &out)
}

func (c *Client) DeleteBinding(ctx context.Context, session string, id int64) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/admin/bindings/%d", id), session, nil, nil)
}

// DiscoveryDocument is the OIDC discovery document White Rabbit serves for its Dex.
type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func (c *Client) Discovery(ctx context.Context) (*DiscoveryDocument, error) {
	var out DiscoveryDocument
	return &out, c.do(ctx, http.MethodGet, "/.well-known/openid-configuration", "", nil, &out)
}

// ProblemsError carries a rejected binding's problems.
type ProblemsError struct {
	Err      *Error
	Problems []string
}

func (e *ProblemsError) Error() string {
	return e.Err.Error() + ":\n  - " + strings.Join(e.Problems, "\n  - ")
}

func (e *ProblemsError) Unwrap() error { return e.Err }

func (c *Client) do(ctx context.Context, method, path, session string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Server+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if session != "" {
		req.Header.Set("Authorization", "Bearer "+session)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach White Rabbit at %s: %w", c.Server, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &Error{Status: resp.StatusCode}
		var problems BindingProblems
		_ = json.Unmarshal(data, e)
		if json.Unmarshal(data, &problems) == nil && len(problems.Problems) > 0 {
			return &ProblemsError{Err: e, Problems: problems.Problems}
		}
		return e
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unexpected answer from %s%s", c.Server, path)
	}
	return nil
}

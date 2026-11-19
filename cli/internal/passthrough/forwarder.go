package passthrough

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CredentialSource issues a short-lived virtual Bunny credential for White Rabbit's proxy.
type CredentialSource func(ctx context.Context) (key string, expires time.Time, err error)

// Forwarder listens on 127.0.0.1 and forwards the bunny child's API calls to White Rabbit's proxy. The child only
// knows a one-time local key; the virtual credential stays in this process and is renewed before it expires, so
// long-running commands never hit its 5-minute lifetime.
type Forwarder struct {
	URL      string // http://127.0.0.1:<port>, the child's BUNNYNET_API_URL
	LocalKey string // the child's BUNNYNET_API_KEY

	listener net.Listener
	server   *http.Server

	mu       sync.Mutex
	key      string
	expires  time.Time
	source   CredentialSource
	debug    io.Writer
	upstream *url.URL
}

// renewBefore is how long before expiry a virtual credential is replaced.
const renewBefore = 60 * time.Second

// StartForwarder starts forwarding to server (a White Rabbit origin).
func StartForwarder(server string, source CredentialSource, transport http.RoundTripper, debug io.Writer) (*Forwarder, error) {
	upstream, err := url.Parse(server)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("cannot listen on 127.0.0.1: %w", err)
	}
	f := &Forwarder{
		URL:      "http://" + listener.Addr().String(),
		LocalKey: "rabbit-local-" + randomString(32),
		listener: listener,
		source:   source,
		debug:    debug,
		upstream: upstream,
	}
	proxy := &httputil.ReverseProxy{
		Rewrite:   f.rewrite,
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			f.logf("rabbit: forwarding %s %s failed: %v", r.Method, r.URL.Path, err)
			writeJSON(w, http.StatusBadGateway, `{"error":"rabbit_forwarding_failed","detail":"White Rabbit could not be reached"}`)
		},
		ModifyResponse: func(resp *http.Response) error {
			f.logf("rabbit: %s %s -> %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode)
			return nil
		},
	}
	f.server = &http.Server{Handler: f.guard(proxy), ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = f.server.Serve(listener) }()
	return f, nil
}

// Close stops the forwarder.
func (f *Forwarder) Close() error { return f.server.Close() }

// guard admits only requests carrying the local key, and attaches a current virtual credential.
func (f *Forwarder) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("AccessKey")), []byte(f.LocalKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, `{"error":"rabbit_local_key_required","detail":"only the bunny process started by rabbit may use this address"}`)
			return
		}
		key, err := f.credential(r.Context())
		if err != nil {
			f.logf("rabbit: %v", err)
			writeJSON(w, http.StatusUnauthorized, `{"error":"rabbit_no_credential","detail":"White Rabbit did not issue a credential; see rabbit's message above"}`)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), credentialKey{}, key))
		next.ServeHTTP(w, r)
	})
}

type credentialKey struct{}

func (f *Forwarder) rewrite(pr *httputil.ProxyRequest) {
	in := pr.In
	target := *f.upstream
	target.Path = "/proxy/api.bunny.net" + MapPath(in.URL.Path)
	target.RawPath = ""
	target.RawQuery = in.URL.RawQuery
	pr.Out.URL = &target
	pr.Out.Host = f.upstream.Host

	// Nothing the child sent as a credential or identity leaves this process; only the virtual credential does.
	for _, h := range []string{"AccessKey", "Authorization", "Cookie", "Proxy-Authorization", "X-Remote-User", "X-Remote-Groups", "X-Remote-Extra"} {
		pr.Out.Header.Del(h)
	}
	pr.Out.Header.Set("AccessKey", in.Context().Value(credentialKey{}).(string))
}

func (f *Forwarder) credential(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.key != "" && time.Until(f.expires) > renewBefore {
		return f.key, nil
	}
	key, expires, err := f.source(ctx)
	if err != nil {
		return "", err
	}
	f.key, f.expires = key, expires
	return key, nil
}

func (f *Forwarder) logf(format string, args ...any) {
	if f.debug != nil {
		fmt.Fprintf(f.debug, format+"\n", args...)
	}
}

// databasePrefixes and mcPrefixes are the first path segments of the Bunny Database and Magic Containers APIs
// (from BunnyCLI's OpenAPI specs). BunnyCLI 0.22.0 drops their /database and /mc prefixes when BUNNYNET_API_URL is
// set; MapPath puts them back. "/v1/pricing" belongs to the core API and is left alone.
var (
	databasePrefixes = []string{"/v1/config", "/v1/databases", "/v1/groups", "/v1/live", "/v2/"}
	mcPrefixes       = []string{"/apps", "/limits", "/log", "/nodes", "/regions", "/registries"}
)

// MapPath turns a path as BunnyCLI sends it into the api.bunny.net path. Already-prefixed paths (as `bunny api`
// sends them, or a BunnyCLI with the bug fixed) are unchanged.
func MapPath(p string) string {
	if p == "" {
		p = "/"
	}
	if hasSegmentPrefix(p, "/database") || hasSegmentPrefix(p, "/mc") {
		return p
	}
	for _, prefix := range databasePrefixes {
		if hasSegmentPrefix(p, strings.TrimSuffix(prefix, "/")) {
			return "/database" + p
		}
	}
	for _, prefix := range mcPrefixes {
		if hasSegmentPrefix(p, prefix) {
			return "/mc" + p
		}
	}
	return p
}

// hasSegmentPrefix matches whole path segments: "/apps" matches "/apps" and "/apps/1" but not "/appsx".
func hasSegmentPrefix(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/") || strings.HasPrefix(p, prefix+"?")
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

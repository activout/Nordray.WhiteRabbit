// Package secrets keeps the interactive White Rabbit session in the operating system's credential store
// (macOS Keychain, Windows Credential Manager, Secret Service on Linux). Nothing is ever written to a plain file:
// without a credential store the session lives only for the current process.
package secrets

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

const service = "nordray-rabbit"

// Session is a White Rabbit CLI session for one server.
type Session struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the session is past (or within a minute of) its expiry.
func (s Session) Expired(now time.Time) bool { return !now.Add(time.Minute).Before(s.ExpiresAt) }

// ErrNotFound means no session is stored for the server.
var ErrNotFound = errors.New("no stored session")

// ErrUnavailable means the operating system has no usable credential store.
var ErrUnavailable = errors.New("no operating system credential store available")

// Store holds sessions keyed by server URL.
type Store interface {
	Get(server string) (Session, error)
	Set(server string, s Session) error
	Delete(server string) error
}

// Keyring is the operating system credential store.
type Keyring struct{}

func (Keyring) Get(server string) (Session, error) {
	raw, err := keyring.Get(service, server)
	if errors.Is(err, keyring.ErrNotFound) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, errors.Join(ErrUnavailable, err)
	}
	var s Session
	if err := json.Unmarshal([]byte(raw), &s); err != nil || s.Token == "" {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (Keyring) Set(server string, s Session) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := keyring.Set(service, server, string(data)); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

func (Keyring) Delete(server string) error {
	err := keyring.Delete(service, server)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

// Memory is an in-process store, for tests.
type Memory struct {
	mu sync.Mutex
	m  map[string]Session
}

func (m *Memory) Get(server string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.m[server]
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) Set(server string, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]Session{}
	}
	m.m[server] = s
	return nil
}

func (m *Memory) Delete(server string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, server)
	return nil
}

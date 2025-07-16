// Package crooner provides secure session management and authentication helpers for Go web applications.
// It offers a flexible, config-first approach to session configuration, secure cookie handling, and integration with authentication providers such as Azure AD.
// Main features include:
//   - Secure, customizable session cookie management
//   - Helpers for non-predictable cookie names
//   - Pluggable session backends (SCS, Redis, etc.)
//   - Easy integration with Echo and other web frameworks
//   - Security-focused defaults and best practices
package crooner

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	http "net/http"
	"time"

	scs "github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
)

// SessionManager abstracts session operations for pluggable backends (SCS, etc.)
type SessionManager interface {
	// Get retrieves a value from the session by key
	Get(c echo.Context, key string) (any, error)
	// Set sets a value in the session
	Set(c echo.Context, key string, value any) error
	// Delete removes a value from the session
	Delete(c echo.Context, key string) error
	// Clear removes all values from the session
	Clear(c echo.Context) error
	// Invalidate invalidates the session (expires cookie)
	Invalidate(c echo.Context) error
	// ClearInvalidate removes all values and invalidates the session (expires cookie)
	ClearInvalidate(c echo.Context) error
	// Type-safe helpers
	GetString(c echo.Context, key string) (string, error)
	GetInt(c echo.Context, key string) (int, error)
	GetBool(c echo.Context, key string) (bool, error)
}

// SCSManager implements SessionManager using SCS (github.com/alexedwards/scs/v2)
type SCSManager struct {
	Session *scs.SessionManager
}

func (s *SCSManager) Get(c echo.Context, key string) (any, error) {
	return s.Session.Get(c.Request().Context(), key), nil
}

func (s *SCSManager) Set(c echo.Context, key string, value any) error {
	s.Session.Put(c.Request().Context(), key, value)
	return nil
}

func (s *SCSManager) Delete(c echo.Context, key string) error {
	s.Session.Remove(c.Request().Context(), key)
	return nil
}

func (s *SCSManager) Clear(c echo.Context) error {
	return s.Session.Clear(c.Request().Context())
}

func (s *SCSManager) Invalidate(c echo.Context) error {
	return s.Session.Destroy(c.Request().Context())
}

// Implement for SCSManager:
func (s *SCSManager) ClearInvalidate(c echo.Context) error {
	if err := s.Clear(c); err != nil {
		return err
	}
	return s.Invalidate(c)
}

// Standard reasons for SessionError.
const (
	ReasonNotFound    = "not found"
	ReasonInvalidType = "invalid type"
)

// GetString retrieves a string value from the session by key.
// Returns a *SessionError if the key is missing or the value is not a string.
func (s *SCSManager) GetString(c echo.Context, key string) (string, error) {
	val := s.Session.Get(c.Request().Context(), key)
	if val == nil {
		return "", &SessionError{Key: key, Reason: ReasonNotFound}
	}
	str, ok := val.(string)
	if !ok {
		return "", &SessionError{Key: key, Reason: ReasonInvalidType}
	}
	return str, nil
}

// GetInt retrieves an int value from the session by key.
// Returns a *SessionError if the key is missing or the value is not an int.
func (s *SCSManager) GetInt(c echo.Context, key string) (int, error) {
	val := s.Session.Get(c.Request().Context(), key)
	if val == nil {
		return 0, &SessionError{Key: key, Reason: ReasonNotFound}
	}
	i, ok := val.(int)
	if !ok {
		return 0, &SessionError{Key: key, Reason: ReasonInvalidType}
	}
	return i, nil
}

// GetBool retrieves a bool value from the session by key.
// Returns a *SessionError if the key is missing or the value is not a bool.
func (s *SCSManager) GetBool(c echo.Context, key string) (bool, error) {
	val := s.Session.Get(c.Request().Context(), key)
	if val == nil {
		return false, &SessionError{Key: key, Reason: ReasonNotFound}
	}
	b, ok := val.(bool)
	if !ok {
		return false, &SessionError{Key: key, Reason: ReasonInvalidType}
	}
	return b, nil
}

// SessionConfig holds configuration for the SCS session manager factory.
type SessionConfig struct {
	CookieName     string
	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite http.SameSite
	Lifetime       time.Duration
	Store          scs.Store // optional, for advanced users
}

// DefaultSecureSessionConfig returns a config with secure defaults.
func DefaultSecureSessionConfig() SessionConfig {
	return SessionConfig{
		CookieName:     "crooner-" + randomSuffix(),
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteLaxMode,
		Lifetime:       24 * time.Hour,
		CookiePath:     "/",
	}
}

// SessionOption defines a functional option for SessionConfig.
//
// Use these with NewSCSManager to customize session behavior.
type SessionOption func(*SessionConfig)

// WithCookieName sets the session cookie name.
func WithCookieName(name string) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.CookieName = name
	}
}

// WithCookieDomain sets the session cookie domain.
func WithCookieDomain(domain string) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.CookieDomain = domain
	}
}

// WithCookiePath sets the session cookie path.
func WithCookiePath(path string) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.CookiePath = path
	}
}

// WithCookieSecure sets the session cookie Secure flag.
func WithCookieSecure(secure bool) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.CookieSecure = secure
	}
}

// WithCookieHTTPOnly sets the session cookie HttpOnly flag.
func WithCookieHTTPOnly(httpOnly bool) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.CookieHTTPOnly = httpOnly
	}
}

// WithCookieSameSite sets the session cookie SameSite mode.
func WithCookieSameSite(sameSite http.SameSite) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.CookieSameSite = sameSite
	}
}

// WithLifetime sets the session lifetime.
func WithLifetime(lifetime time.Duration) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.Lifetime = lifetime
	}
}

// WithStore sets the session store backend.
func WithStore(store scs.Store) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.Store = store
	}
}

// WithPersistentCookieName sets the cookie name using a persistent, non-guessable hash
// derived from the provided secret and app name.
func WithPersistentCookieName(secret, appName string) SessionOption {
	return func(cfg *SessionConfig) {
		suffix := PersistentCookieSuffix(secret, appName)
		cfg.CookieName = "crooner-" + suffix
	}
}

// NewSCSManagerWithConfig returns a configured SCSManager and the underlying *scs.SessionManager.
// Returns an error if CookieName is not set.
func NewSCSManagerWithConfig(cfg SessionConfig) (*SCSManager, *scs.SessionManager, error) {
	if cfg.CookieName == "" {
		return nil, nil, fmt.Errorf("you must set CookieName in SessionConfig")
	}
	scsMgr := scs.New()
	scsMgr.Cookie.Name = cfg.CookieName
	scsMgr.Cookie.HttpOnly = cfg.CookieHTTPOnly
	scsMgr.Cookie.Secure = cfg.CookieSecure
	scsMgr.Cookie.SameSite = cfg.CookieSameSite
	scsMgr.Cookie.Domain = cfg.CookieDomain
	scsMgr.Cookie.Path = cfg.CookiePath
	scsMgr.Cookie.Persist = true
	scsMgr.Lifetime = cfg.Lifetime
	if cfg.Store != nil {
		scsMgr.Store = cfg.Store
	}
	return &SCSManager{Session: scsMgr}, scsMgr, nil
}

// NewSCSManager creates a new SCSManager using functional options.
// Returns an error if required configuration is missing.
func NewSCSManager(opts ...SessionOption) (*SCSManager, *scs.SessionManager, error) {
	cfg := DefaultSecureSessionConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return NewSCSManagerWithConfig(cfg)
}

// PersistentCookieSuffix returns a non-guessable, persistent hash for use as a cookie name suffix.
// Use a strong session secret and (optionally) an app name for uniqueness.
func PersistentCookieSuffix(secret, appName string) string {
	h := sha256.New()
	h.Write([]byte(secret))
	h.Write([]byte(appName))
	return hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 hex chars for brevity
}

// randomSuffix returns a random 16-character hex string for cookie names.
func randomSuffix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Example usage of NewSCSManager.
//
//	package main
//	import (
//		"github.com/catgoose/crooner"
//		"time"
//	)
//	func main() {
//		suffix := crooner.PersistentCookieSuffix("mysecret", "myapp")
//		sessionMgr, scsMgr, err := crooner.NewSCSManager(
//			crooner.WithCookieName("crooner-"+suffix),
//			crooner.WithLifetime(12*time.Hour),
//		)
//		if err != nil {
//			panic(err)
//		}
//		_ = sessionMgr
//		_ = scsMgr
//	}
//
// Note: SessionManager.Set/Get accept values of type 'any'.
// It is recommended to use simple, serializable types (string, int, etc.) for session values.

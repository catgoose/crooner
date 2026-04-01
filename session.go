// Package crooner provides secure session management and authentication helpers for Go web applications.
// It offers a flexible, config-first approach to session configuration, secure cookie handling, and integration with OIDC-compliant authentication providers.
// Main features include:
//   - Secure, customizable session cookie management
//   - Helpers for non-predictable cookie names
//   - Pluggable session backends (SCS, Redis, etc.)
//   - Easy integration with net/http and other web frameworks
//   - Security-focused defaults and best practices
package crooner

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	scs "github.com/alexedwards/scs/v2"
)

// SessionManager abstracts session operations for pluggable backends (SCS, etc.)
type SessionManager interface {
	// Get retrieves a value from the session by key
	Get(r *http.Request, key string) (any, error)
	// Set sets a value in the session
	Set(r *http.Request, key string, value any) error
	// Delete removes a value from the session
	Delete(r *http.Request, key string) error
	// Clear removes all values from the session
	Clear(r *http.Request) error
	// Invalidate invalidates the session (expires cookie)
	Invalidate(r *http.Request) error
	// ClearInvalidate removes all values and invalidates the session (expires cookie)
	ClearInvalidate(r *http.Request) error
}

// SessionTokenRenewer is an optional interface for session backends that can regenerate the session token (e.g. to prevent session fixation). If SessionManager implements this, it will be called after successful login before storing user data.
type SessionTokenRenewer interface {
	RenewToken(r *http.Request) error
}

// SCSManager implements SessionManager using SCS (github.com/alexedwards/scs/v2)
type SCSManager struct {
	Session    *scs.SessionManager
	cookieName string
}

func (s *SCSManager) Get(r *http.Request, key string) (any, error) {
	return s.Session.Get(r.Context(), key), nil
}

func (s *SCSManager) Set(r *http.Request, key string, value any) error {
	s.Session.Put(r.Context(), key, value)
	return nil
}

func (s *SCSManager) Delete(r *http.Request, key string) error {
	s.Session.Remove(r.Context(), key)
	return nil
}

func (s *SCSManager) Clear(r *http.Request) error {
	return s.Session.Clear(r.Context())
}

func (s *SCSManager) Invalidate(r *http.Request) error {
	return s.Session.Destroy(r.Context())
}

// ClearInvalidate removes all values and invalidates the session (expires cookie).
func (s *SCSManager) ClearInvalidate(r *http.Request) error {
	if err := s.Clear(r); err != nil {
		return err
	}
	return s.Invalidate(r)
}

// RenewToken regenerates the session token to prevent session fixation. Call after privilege-level change (e.g. login).
func (s *SCSManager) RenewToken(r *http.Request) error {
	return s.Session.RenewToken(r.Context())
}

// SessionError represents an error related to session operations.
type SessionError struct {
	Err    error  // Optional wrapped error
	Key    string // The session key involved
	Reason string // A human-readable reason for the error
}

func (e *SessionError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("session error for key %q: %s: %v", e.Key, e.Reason, e.Err)
	}
	return fmt.Sprintf("session error for key %q: %s", e.Key, e.Reason)
}

// Unwrap returns the wrapped error, if any.
func (e *SessionError) Unwrap() error { return e.Err }

// IsSessionError checks if an error is a SessionError
func IsSessionError(err error) bool {
	var sessionErr *SessionError
	return errors.As(err, &sessionErr)
}

// AsSessionError attempts to convert an error to SessionError
func AsSessionError(err error) (*SessionError, bool) {
	var sessionErr *SessionError
	if errors.As(err, &sessionErr) {
		return sessionErr, true
	}
	return nil, false
}

// SessionErrorResponse creates a JSON-friendly response from a SessionError for app-level use (e.g. your own routes). Auth routes use RFC 7807/9457 ProblemDetails instead.
func SessionErrorResponse(err error) map[string]any {
	if sessionErr, ok := AsSessionError(err); ok {
		return map[string]any{
			"error":  "session_error",
			"key":    sessionErr.Key,
			"reason": sessionErr.Reason,
		}
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return map[string]any{
		"error":   "unknown_error",
		"message": msg,
	}
}

// Standard reasons for SessionError.
const (
	ReasonNotFound    = "not found"
	ReasonInvalidType = "invalid type"
)

// Common session key constants for consistency
const (
	SessionKeyUser         = "user"
	SessionKeyOAuthState   = "oauth_state"
	SessionKeyCodeVerifier = "code_verifier"
	SessionKeyOAuthNonce   = "oauth_nonce"
)

func getSessionTyped[T any](sm SessionManager, r *http.Request, key string, zero T, check func(any) (T, bool)) (T, error) {
	val, err := sm.Get(r, key)
	if err != nil || val == nil {
		return zero, &SessionError{Key: key, Reason: ReasonNotFound}
	}
	v, ok := check(val)
	if !ok {
		return zero, &SessionError{Key: key, Reason: ReasonInvalidType}
	}
	return v, nil
}

// GetString retrieves a string value from the session by key.
// Returns a *SessionError if the key is missing or the value is not a string.
func GetString(sm SessionManager, r *http.Request, key string) (string, error) {
	return getSessionTyped(sm, r, key, "", func(a any) (string, bool) { s, ok := a.(string); return s, ok })
}

// GetInt retrieves an int value from the session by key.
// Returns a *SessionError if the key is missing or the value is not an int.
func GetInt(sm SessionManager, r *http.Request, key string) (int, error) {
	return getSessionTyped(sm, r, key, 0, func(a any) (int, bool) { i, ok := a.(int); return i, ok })
}

// GetBool retrieves a bool value from the session by key.
// Returns a *SessionError if the key is missing or the value is not a bool.
func GetBool(sm SessionManager, r *http.Request, key string) (bool, error) {
	return getSessionTyped(sm, r, key, false, func(a any) (bool, bool) { b, ok := a.(bool); return b, ok })
}

// SaveSessionValueClaims stores configured claims from the ID token into the session.
// valueClaims maps session keys to claim names (e.g. {"roles": "realm_roles"}).
// Slice/array claim values are normalized to []string.
func SaveSessionValueClaims(sm SessionManager, r *http.Request, claims map[string]any, valueClaims map[string]string) error {
	if valueClaims == nil {
		return nil
	}
	for key, claim := range valueClaims {
		if val, ok := claims[claim]; ok {
			if slice, isSlice := val.([]any); isSlice {
				var sliceStrings []string
				for _, role := range slice {
					if strRole, isString := role.(string); isString {
						sliceStrings = append(sliceStrings, strRole)
					}
				}
				val = sliceStrings
			}
			if err := sm.Set(r, key, val); err != nil {
				return err
			}
		}
	}
	return nil
}

// SessionConfig holds configuration for the SCS session manager factory.
type SessionConfig struct {
	Store          scs.Store
	CookieName     string
	CookieDomain   string
	CookiePath     string
	CookieSameSite http.SameSite
	Lifetime       time.Duration
	CookieSecure   bool
	CookieHTTPOnly bool
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
	if cfg.Lifetime <= 0 {
		return nil, nil, fmt.Errorf("lifetime must be greater than 0")
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
	return &SCSManager{Session: scsMgr, cookieName: cfg.CookieName}, scsMgr, nil
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

// GetCookieName returns the session cookie name used by this manager.
func (s *SCSManager) GetCookieName() string {
	return s.cookieName
}

// GetSCSManager returns the underlying SCS session manager for advanced usage.
// This allows users to access SCS-specific features when needed.
func (s *SCSManager) GetSCSManager() *scs.SessionManager {
	return s.Session
}

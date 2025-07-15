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

// NewSCSManagerWithConfig returns a configured SCSManager and the underlying *scs.SessionManager.
// CookieName must be set in cfg.
func NewSCSManagerWithConfig(cfg SessionConfig) (*SCSManager, *scs.SessionManager) {
	if cfg.CookieName == "" {
		panic("You must set CookieName in SessionConfig")
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
	return &SCSManager{Session: scsMgr}, scsMgr
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

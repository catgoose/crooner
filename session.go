package crooner

import (
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

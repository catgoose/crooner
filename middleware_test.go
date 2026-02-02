package crooner

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestSecurityHeadersMiddleware_NilConfig_Defaults(t *testing.T) {
	e := echo.New()
	e.Use(SecurityHeadersMiddleware(nil))
	e.GET("/", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	h := rec.Header()
	if h.Get("Content-Security-Policy") != "default-src 'self'" {
		t.Errorf("Content-Security-Policy = %q", h.Get("Content-Security-Policy"))
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q", h.Get("X-Frame-Options"))
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", h.Get("X-Content-Type-Options"))
	}
	if h.Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q", h.Get("Referrer-Policy"))
	}
	if h.Get("X-XSS-Protection") != "1; mode=block" {
		t.Errorf("X-XSS-Protection = %q", h.Get("X-XSS-Protection"))
	}
	if rec.Code != 200 {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestSecurityHeadersMiddleware_CustomConfig(t *testing.T) {
	cfg := &SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'none'",
		XFrameOptions:         "SAMEORIGIN",
	}
	e := echo.New()
	e.Use(SecurityHeadersMiddleware(cfg))
	e.GET("/", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	h := rec.Header()
	if h.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Errorf("Content-Security-Policy = %q", h.Get("Content-Security-Policy"))
	}
	if h.Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q", h.Get("X-Frame-Options"))
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q (should still default)", h.Get("X-Content-Type-Options"))
	}
}

func TestSecurityHeadersMiddleware_HSTS_HTTPS(t *testing.T) {
	cfg := &SecurityHeadersConfig{StrictTransportSecurity: "max-age=3600"}
	e := echo.New()
	e.Use(SecurityHeadersMiddleware(cfg))
	e.GET("/", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Header().Get("Strict-Transport-Security") != "max-age=3600" {
		t.Errorf("Strict-Transport-Security = %q", rec.Header().Get("Strict-Transport-Security"))
	}
}

func TestSecurityHeadersMiddleware_HSTS_HTTP(t *testing.T) {
	cfg := &SecurityHeadersConfig{StrictTransportSecurity: "max-age=3600"}
	e := echo.New()
	e.Use(SecurityHeadersMiddleware(cfg))
	e.GET("/", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.URL.Scheme = "http"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Errorf("Strict-Transport-Security should be unset for HTTP, got %q", rec.Header().Get("Strict-Transport-Security"))
	}
}

func TestRequireAuth_ExemptPath_NextCalled(t *testing.T) {
	sm := newMapSessionManager()
	routes := &AuthRoutes{Login: "/login", Callback: "/callback", Logout: "/logout"}
	e := echo.New()
	e.Use(RequireAuth(sm, routes))
	e.GET("/login", func(c echo.Context) error { return c.String(200, "login") })
	e.GET("/callback", func(c echo.Context) error { return c.String(200, "callback") })
	e.GET("/logout", func(c echo.Context) error { return c.String(200, "logout") })
	e.GET("/protected", func(c echo.Context) error { return c.String(200, "protected") })

	for _, path := range []string{"/login", "/callback", "/logout"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("%s: status = %d, want 200", path, rec.Code)
		}
	}
}

func TestRequireAuth_NoSessionUser_RedirectToLogin(t *testing.T) {
	sm := newMapSessionManager()
	routes := &AuthRoutes{Login: "/login", Callback: "/callback", Logout: "/logout"}
	e := echo.New()
	e.Use(RequireAuth(sm, routes))
	e.GET("/protected", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != 302 {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	expectedPrefix := "/login?redirect="
	if len(loc) < len(expectedPrefix) || loc[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Location = %q, want prefix %q", loc, expectedPrefix)
	}
	decoded, err := url.QueryUnescape(loc[len(expectedPrefix):])
	if err != nil {
		t.Fatalf("QueryUnescape: %v", err)
	}
	if decoded != "/protected" {
		t.Errorf("redirect param = %q, want /protected", decoded)
	}
}

func TestRequireAuth_SessionUser_NextCalled(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, SessionKeyUser, "alice")

	routes := &AuthRoutes{Login: "/login", Callback: "/callback", Logout: "/logout"}
	e := echo.New()
	e.Use(RequireAuth(sm, routes))
	e.GET("/protected", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireAuth_AuthExempt_NextCalled(t *testing.T) {
	sm := newMapSessionManager()
	routes := &AuthRoutes{
		Login: "/login", Callback: "/callback", Logout: "/logout",
		AuthExempt: []string{"/health"},
	}
	e := echo.New()
	e.Use(RequireAuth(sm, routes))
	e.GET("/health", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

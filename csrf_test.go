package crooner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestCSRF_UnsafeMethod_ValidToken_Passes(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, SessionKeyCSRFToken, "secret")
	_ = sm.Set(c, SessionKeyUser, "user")

	e := echo.New()
	e.Use(CSRF(sm))
	e.POST("/submit", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-CSRF-Token", "secret")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCSRF_UnsafeMethod_InvalidToken_403(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, SessionKeyCSRFToken, "secret")
	_ = sm.Set(c, SessionKeyUser, "user")

	e := echo.New()
	e.Use(CSRF(sm))
	e.POST("/submit", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-CSRF-Token", "wrong")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != 403 {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestCSRF_UnsafeMethod_ExemptPath_Passes(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, SessionKeyCSRFToken, "secret")
	_ = sm.Set(c, SessionKeyUser, "user")

	e := echo.New()
	e.Use(CSRF(sm, CSRFExemptPaths([]string{"/webhook/"})))
	e.POST("/webhook/receive", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodPost, "/webhook/receive", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCSRF_SafeMethod_SetsHeaderWhenUserPresent(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, SessionKeyUser, "user")

	e := echo.New()
	e.Use(CSRF(sm))
	e.GET("/", func(c echo.Context) error { return c.String(200, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-CSRF-Token") == "" {
		t.Error("X-CSRF-Token header not set on safe request with user in session")
	}
}

func TestIsCSRFExemptPath(t *testing.T) {
	tests := []struct {
		path   string
		exempt []string
		want   bool
	}{
		{"/webhook/", []string{"/webhook/"}, true},
		{"/webhook/foo", []string{"/webhook/"}, true},
		{"/webhook", []string{"/webhook/"}, false},
		{"/api", []string{"/webhook/"}, false},
		{"/", []string{}, false},
	}
	for _, tc := range tests {
		got := isCSRFExemptPath(tc.path, tc.exempt)
		if got != tc.want {
			t.Errorf("isCSRFExemptPath(%q, %v) = %v, want %v", tc.path, tc.exempt, got, tc.want)
		}
	}
}

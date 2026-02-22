package crooner

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// mapSessionManager is an in-memory SessionManager for tests.
type mapSessionManager struct {
	data map[string]any
}

func newMapSessionManager() *mapSessionManager {
	return &mapSessionManager{data: make(map[string]any)}
}

func (m *mapSessionManager) Get(c echo.Context, key string) (any, error) {
	v, ok := m.data[key]
	if !ok {
		return nil, nil
	}
	return v, nil
}

func (m *mapSessionManager) Set(c echo.Context, key string, value any) error {
	m.data[key] = value
	return nil
}

func (m *mapSessionManager) Delete(c echo.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mapSessionManager) Clear(c echo.Context) error {
	m.data = make(map[string]any)
	return nil
}

func (m *mapSessionManager) Invalidate(c echo.Context) error {
	return nil
}

func (m *mapSessionManager) ClearInvalidate(c echo.Context) error {
	m.data = make(map[string]any)
	return nil
}

type failingSessionManager struct {
	data map[string]any
}

func (f *failingSessionManager) Get(c echo.Context, key string) (any, error) {
	v, ok := f.data[key]
	if !ok {
		return nil, nil
	}
	return v, nil
}

var errSetFailed = errors.New("set failed")

func (f *failingSessionManager) Set(c echo.Context, key string, value any) error {
	return errSetFailed
}

func (f *failingSessionManager) Delete(c echo.Context, key string) error {
	delete(f.data, key)
	return nil
}

func (f *failingSessionManager) Clear(c echo.Context) error {
	f.data = make(map[string]any)
	return nil
}

func (f *failingSessionManager) Invalidate(c echo.Context) error {
	return nil
}

func (f *failingSessionManager) ClearInvalidate(c echo.Context) error {
	f.data = make(map[string]any)
	return nil
}

func echoContext() echo.Context {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestSessionError_Unwrap(t *testing.T) {
	inner := errors.New("connection refused")
	se := &SessionError{Key: "user", Reason: "store failure", Err: inner}

	if se.Unwrap() != inner {
		t.Error("SessionError.Unwrap() != inner")
	}
	if !errors.Is(se, inner) {
		t.Error("errors.Is(SessionError, inner) = false")
	}
	if !strings.Contains(se.Error(), "connection refused") {
		t.Errorf("Error() = %q, want to contain wrapped error", se.Error())
	}
	if !strings.Contains(se.Error(), "store failure") {
		t.Errorf("Error() = %q, want to contain reason", se.Error())
	}

	// Verify errors.As works through the chain
	wrapped := fmt.Errorf("outer: %w", se)
	var target *SessionError
	if !errors.As(wrapped, &target) {
		t.Error("errors.As(wrapped, *SessionError) = false")
	}
	if target.Key != "user" {
		t.Errorf("Key = %q, want user", target.Key)
	}

	// Nil Err still works
	seNoErr := &SessionError{Key: "k", Reason: "r"}
	if seNoErr.Unwrap() != nil {
		t.Error("SessionError with nil Err: Unwrap() != nil")
	}
	if strings.Contains(seNoErr.Error(), ":") && strings.Count(seNoErr.Error(), ":") > 1 {
		// Just verify it doesn't panic and has sensible output
	}
}

func TestPersistentCookieSuffix_Deterministic(t *testing.T) {
	a := PersistentCookieSuffix("secret", "myapp")
	b := PersistentCookieSuffix("secret", "myapp")
	if a != b {
		t.Errorf("PersistentCookieSuffix not deterministic: %q != %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("len(suffix) = %d, want 16", len(a))
	}
}

func TestPersistentCookieSuffix_DifferentInputs_DifferentOutputs(t *testing.T) {
	a := PersistentCookieSuffix("secret1", "app")
	b := PersistentCookieSuffix("secret2", "app")
	c := PersistentCookieSuffix("secret", "app1")
	if a == b || a == c || b == c {
		t.Error("different inputs should produce different suffixes")
	}
}

func TestGetString_Found(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, "user", "alice")
	got, err := GetString(sm, c, "user")
	if err != nil {
		t.Fatalf("GetString: %v", err)
	}
	if got != "alice" {
		t.Errorf("GetString = %q, want alice", got)
	}
}

func TestGetString_NotFound(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_, err := GetString(sm, c, "missing")
	if err == nil {
		t.Fatal("GetString(missing) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetString(missing): not SessionError: %v", err)
	}
	if se, ok := AsSessionError(err); ok && se.Reason != ReasonNotFound {
		t.Errorf("reason = %q, want %q", se.Reason, ReasonNotFound)
	}
}

func TestGetString_InvalidType(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, "user", 123)
	_, err := GetString(sm, c, "user")
	if err == nil {
		t.Fatal("GetString(int) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetString(int): not SessionError: %v", err)
	}
	if se, ok := AsSessionError(err); ok && se.Reason != ReasonInvalidType {
		t.Errorf("reason = %q, want %q", se.Reason, ReasonInvalidType)
	}
}

func TestGetInt_Found(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, "count", 42)
	got, err := GetInt(sm, c, "count")
	if err != nil {
		t.Fatalf("GetInt: %v", err)
	}
	if got != 42 {
		t.Errorf("GetInt = %d, want 42", got)
	}
}

func TestGetInt_NotFound(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_, err := GetInt(sm, c, "missing")
	if err == nil {
		t.Fatal("GetInt(missing) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetInt(missing): not SessionError: %v", err)
	}
}

func TestGetInt_InvalidType(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, "count", "not-an-int")
	_, err := GetInt(sm, c, "count")
	if err == nil {
		t.Fatal("GetInt(string) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetInt(string): not SessionError: %v", err)
	}
}

func TestGetBool_Found(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, "ok", true)
	got, err := GetBool(sm, c, "ok")
	if err != nil {
		t.Fatalf("GetBool: %v", err)
	}
	if !got {
		t.Error("GetBool = false, want true")
	}
}

func TestGetBool_NotFound(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_, err := GetBool(sm, c, "missing")
	if err == nil {
		t.Fatal("GetBool(missing) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetBool(missing): not SessionError: %v", err)
	}
}

func TestGetBool_InvalidType(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, "ok", "yes")
	_, err := GetBool(sm, c, "ok")
	if err == nil {
		t.Fatal("GetBool(string) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetBool(string): not SessionError: %v", err)
	}
}

func TestSaveSessionValueClaims_NilValueClaims(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	err := SaveSessionValueClaims(sm, c, map[string]any{"roles": []string{"admin"}}, nil)
	if err != nil {
		t.Errorf("SaveSessionValueClaims(nil valueClaims) = %v", err)
	}
	_, err = GetString(sm, c, "roles")
	if err == nil {
		t.Error("expected no session key set")
	}
}

func TestSaveSessionValueClaims_StringClaim(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	claims := map[string]any{"email": "a@b.com"}
	valueClaims := []map[string]string{{"email": "email"}}
	err := SaveSessionValueClaims(sm, c, claims, valueClaims)
	if err != nil {
		t.Fatalf("SaveSessionValueClaims: %v", err)
	}
	got, err := GetString(sm, c, "email")
	if err != nil {
		t.Fatalf("GetString: %v", err)
	}
	if got != "a@b.com" {
		t.Errorf("email = %q, want a@b.com", got)
	}
}

func TestSaveSessionValueClaims_SliceClaimNormalized(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	claims := map[string]any{"roles": []any{"admin", "user"}}
	valueClaims := []map[string]string{{"roles": "roles"}}
	err := SaveSessionValueClaims(sm, c, claims, valueClaims)
	if err != nil {
		t.Fatalf("SaveSessionValueClaims: %v", err)
	}
	val, _ := sm.Get(c, "roles")
	sl, ok := val.([]string)
	if !ok {
		t.Fatalf("roles = %T, want []string", val)
	}
	if len(sl) != 2 || sl[0] != "admin" || sl[1] != "user" {
		t.Errorf("roles = %v", sl)
	}
}

func TestSaveSessionValueClaims_MissingClaim(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	claims := map[string]any{"email": "a@b.com"}
	valueClaims := []map[string]string{{"roles": "roles"}}
	err := SaveSessionValueClaims(sm, c, claims, valueClaims)
	if err != nil {
		t.Fatalf("SaveSessionValueClaims: %v", err)
	}
	_, err = GetString(sm, c, "roles")
	if err == nil {
		t.Error("roles should not be set when claim missing")
	}
}

func TestSaveSessionValueClaims_SetFails(t *testing.T) {
	fail := &failingSessionManager{data: make(map[string]any)}
	c := echoContext()
	claims := map[string]any{"email": "a@b.com"}
	valueClaims := []map[string]string{{"email": "email"}}
	err := SaveSessionValueClaims(fail, c, claims, valueClaims)
	if err != errSetFailed {
		t.Errorf("SaveSessionValueClaims = %v, want errSetFailed", err)
	}
}

func TestSessionErrorResponse_SessionError(t *testing.T) {
	se := &SessionError{Key: "user", Reason: ReasonNotFound}
	resp := SessionErrorResponse(se)
	if resp["error"] != "session_error" {
		t.Errorf("error = %q", resp["error"])
	}
	if resp["key"] != "user" {
		t.Errorf("key = %q", resp["key"])
	}
	if resp["reason"] != ReasonNotFound {
		t.Errorf("reason = %q", resp["reason"])
	}
}

func TestSessionErrorResponse_NonSessionError(t *testing.T) {
	resp := SessionErrorResponse(errors.New("other"))
	if resp["error"] != "unknown_error" {
		t.Errorf("error = %q", resp["error"])
	}
	if resp["message"] != "other" {
		t.Errorf("message = %q", resp["message"])
	}
}

func TestSessionErrorResponse_Nil(t *testing.T) {
	resp := SessionErrorResponse(nil)
	if resp["error"] != "unknown_error" {
		t.Errorf("error = %q", resp["error"])
	}
	if resp["message"] != "" {
		t.Errorf("message = %q, want empty", resp["message"])
	}
}

func TestNewSCSManagerWithConfig_EmptyCookieName(t *testing.T) {
	cfg := SessionConfig{CookieName: "", Lifetime: time.Hour}
	_, _, err := NewSCSManagerWithConfig(cfg)
	if err == nil {
		t.Fatal("NewSCSManagerWithConfig(empty CookieName) = nil")
	}
	if err.Error() != "you must set CookieName in SessionConfig" {
		t.Errorf("err = %q", err.Error())
	}
}

func TestNewSCSManagerWithConfig_ZeroLifetime(t *testing.T) {
	cfg := SessionConfig{CookieName: "test", Lifetime: 0}
	_, _, err := NewSCSManagerWithConfig(cfg)
	if err == nil {
		t.Fatal("NewSCSManagerWithConfig(Lifetime 0) = nil")
	}
	if err.Error() != "lifetime must be greater than 0" {
		t.Errorf("err = %q", err.Error())
	}
}

func TestNewSCSManagerWithConfig_Valid(t *testing.T) {
	cfg := SessionConfig{
		CookieName:     "test-cookie",
		Lifetime:       2 * time.Hour,
		CookieSecure:   true,
		CookieHTTPOnly: true,
	}
	mgr, scsMgr, err := NewSCSManagerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewSCSManagerWithConfig: %v", err)
	}
	if mgr == nil || scsMgr == nil {
		t.Fatal("manager or scsMgr nil")
	}
	if mgr.GetCookieName() != "test-cookie" {
		t.Errorf("GetCookieName = %q", mgr.GetCookieName())
	}
	if scsMgr.Lifetime != 2*time.Hour {
		t.Errorf("Lifetime = %v", scsMgr.Lifetime)
	}
}

func TestNewSCSManager_WithOptions(t *testing.T) {
	mgr, _, err := NewSCSManager(WithCookieName("custom"), WithLifetime(time.Hour))
	if err != nil {
		t.Fatalf("NewSCSManager: %v", err)
	}
	if mgr.GetCookieName() != "custom" {
		t.Errorf("GetCookieName = %q", mgr.GetCookieName())
	}
}

func TestSCSManager_GetCookieName(t *testing.T) {
	cfg := SessionConfig{CookieName: "my-cookie", Lifetime: time.Hour}
	mgr, _, err := NewSCSManagerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewSCSManagerWithConfig: %v", err)
	}
	if mgr.GetCookieName() != "my-cookie" {
		t.Errorf("GetCookieName = %q", mgr.GetCookieName())
	}
}

func TestMapSessionManager_ClearInvalidate(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	_ = sm.Set(c, "user", "alice")
	_ = sm.ClearInvalidate(c)
	_, err := GetString(sm, c, "user")
	if err == nil {
		t.Error("GetString after ClearInvalidate = nil error")
	}
}

func TestSCSManager_Operations(t *testing.T) {
	mgr, scsMgr, err := NewSCSManager(
		WithCookieName("test-ops"),
		WithLifetime(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewSCSManager: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	var testErr error
	handler := scsMgr.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, httptest.NewRecorder())

		// Set
		if err := mgr.Set(c, "key1", "value1"); err != nil {
			testErr = fmt.Errorf("Set: %w", err)
			return
		}

		// Get
		val, err := mgr.Get(c, "key1")
		if err != nil {
			testErr = fmt.Errorf("Get: %w", err)
			return
		}
		if val != "value1" {
			testErr = fmt.Errorf("Get = %v, want value1", val)
			return
		}

		// Delete
		if err := mgr.Delete(c, "key1"); err != nil {
			testErr = fmt.Errorf("Delete: %w", err)
			return
		}
		val, _ = mgr.Get(c, "key1")
		if val != nil {
			testErr = fmt.Errorf("Get after Delete = %v, want nil", val)
			return
		}

		// Set again, then Clear
		_ = mgr.Set(c, "a", "1")
		_ = mgr.Set(c, "b", "2")
		if err := mgr.Clear(c); err != nil {
			testErr = fmt.Errorf("Clear: %w", err)
			return
		}
		v, _ := mgr.Get(c, "a")
		if v != nil {
			testErr = fmt.Errorf("Get after Clear = %v, want nil", v)
			return
		}

		// Invalidate
		_ = mgr.Set(c, "x", "y")
		if err := mgr.Invalidate(c); err != nil {
			testErr = fmt.Errorf("Invalidate: %w", err)
			return
		}

		// ClearInvalidate
		_ = mgr.Set(c, "z", "w")
		if err := mgr.ClearInvalidate(c); err != nil {
			testErr = fmt.Errorf("ClearInvalidate: %w", err)
			return
		}
	}))
	handler.ServeHTTP(rec, req)
	if testErr != nil {
		t.Fatal(testErr)
	}
}

func TestSCSManager_RenewToken(t *testing.T) {
	mgr, scsMgr, err := NewSCSManager(
		WithCookieName("test-renew"),
		WithLifetime(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewSCSManager: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	var testErr error
	handler := scsMgr.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, httptest.NewRecorder())
		_ = mgr.Set(c, "user", "alice")
		if err := mgr.RenewToken(c); err != nil {
			testErr = fmt.Errorf("RenewToken: %w", err)
			return
		}
		// Verify data survives renewal
		val, err := mgr.Get(c, "user")
		if err != nil {
			testErr = fmt.Errorf("Get after RenewToken: %w", err)
			return
		}
		if val != "alice" {
			testErr = fmt.Errorf("Get after RenewToken = %v, want alice", val)
		}
	}))
	handler.ServeHTTP(rec, req)
	if testErr != nil {
		t.Fatal(testErr)
	}
}

func TestWithSessionOptions(t *testing.T) {
	mgr, scsMgr, err := NewSCSManager(
		WithCookieDomain("example.com"),
		WithCookiePath("/app"),
		WithCookieSecure(false),
		WithCookieHTTPOnly(false),
		WithCookieSameSite(http.SameSiteStrictMode),
		WithLifetime(2*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewSCSManager: %v", err)
	}
	if mgr == nil || scsMgr == nil {
		t.Fatal("nil manager")
	}
	if scsMgr.Cookie.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", scsMgr.Cookie.Domain)
	}
	if scsMgr.Cookie.Path != "/app" {
		t.Errorf("Path = %q, want /app", scsMgr.Cookie.Path)
	}
	if scsMgr.Cookie.Secure {
		t.Error("Secure = true, want false")
	}
	if scsMgr.Cookie.HttpOnly {
		t.Error("HttpOnly = true, want false")
	}
	if scsMgr.Cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want StrictMode", scsMgr.Cookie.SameSite)
	}
	if scsMgr.Lifetime != 2*time.Hour {
		t.Errorf("Lifetime = %v, want 2h", scsMgr.Lifetime)
	}
}

func TestWithStore(t *testing.T) {
	// WithStore(nil) should still work (uses default in-memory store)
	mgr, _, err := NewSCSManager(WithStore(nil))
	if err != nil {
		t.Fatalf("NewSCSManager with nil store: %v", err)
	}
	if mgr == nil {
		t.Fatal("nil manager")
	}
}

func TestWithPersistentCookieName(t *testing.T) {
	mgr, _, err := NewSCSManager(WithPersistentCookieName("secret", "myapp"))
	if err != nil {
		t.Fatalf("NewSCSManager: %v", err)
	}
	expected := "crooner-" + PersistentCookieSuffix("secret", "myapp")
	if mgr.GetCookieName() != expected {
		t.Errorf("GetCookieName = %q, want %q", mgr.GetCookieName(), expected)
	}
}

func TestGetSCSManager(t *testing.T) {
	mgr, scsMgr, err := NewSCSManager(WithCookieName("test-get-scs"), WithLifetime(time.Hour))
	if err != nil {
		t.Fatalf("NewSCSManager: %v", err)
	}
	if mgr.GetSCSManager() != scsMgr {
		t.Error("GetSCSManager() != scsMgr")
	}
}

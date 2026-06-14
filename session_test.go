package crooner

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mapSessionManager is an in-memory SessionManager for tests.
type mapSessionManager struct {
	data map[string]any
}

func newMapSessionManager() *mapSessionManager {
	return &mapSessionManager{data: make(map[string]any)}
}

func (m *mapSessionManager) Get(r *http.Request, key string) (any, error) {
	v, ok := m.data[key]
	if !ok {
		return nil, nil
	}
	return v, nil
}

func (m *mapSessionManager) Set(r *http.Request, key string, value any) error {
	m.data[key] = value
	return nil
}

func (m *mapSessionManager) Delete(r *http.Request, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mapSessionManager) Clear(r *http.Request) error {
	m.data = make(map[string]any)
	return nil
}

func (m *mapSessionManager) Invalidate(r *http.Request) error {
	return nil
}

func (m *mapSessionManager) ClearInvalidate(r *http.Request) error {
	m.data = make(map[string]any)
	return nil
}

type failingSessionManager struct {
	data map[string]any
}

func (f *failingSessionManager) Get(r *http.Request, key string) (any, error) {
	v, ok := f.data[key]
	if !ok {
		return nil, nil
	}
	return v, nil
}

var errSetFailed = errors.New("set failed")

func (f *failingSessionManager) Set(r *http.Request, key string, value any) error {
	return errSetFailed
}

func (f *failingSessionManager) Delete(r *http.Request, key string) error {
	delete(f.data, key)
	return nil
}

func (f *failingSessionManager) Clear(r *http.Request) error {
	f.data = make(map[string]any)
	return nil
}

func (f *failingSessionManager) Invalidate(r *http.Request) error {
	return nil
}

func (f *failingSessionManager) ClearInvalidate(r *http.Request) error {
	f.data = make(map[string]any)
	return nil
}

func testRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/", nil)
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

func TestDeriveSessionCookieName(t *testing.T) {
	tests := []struct {
		name    string
		appName string
		want    string
	}{
		{
			name:    "simple",
			appName: "Annex",
			want:    "crooner-annex",
		},
		{
			name:    "spaces and punctuation",
			appName: "Annex Admin: Prod!",
			want:    "crooner-annex-admin-prod",
		},
		{
			name:    "collapses separators",
			appName: "  My---App...API  ",
			want:    "crooner-my-app-api",
		},
		{
			name:    "non ascii falls back to separators",
			appName: "Café Portal",
			want:    "crooner-caf-portal",
		},
		{
			name:    "empty falls back",
			appName: "",
			want:    "crooner-session",
		},
		{
			name:    "only punctuation falls back",
			appName: " !@#$ ",
			want:    "crooner-session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveSessionCookieName(tt.appName)
			if got != tt.want {
				t.Fatalf("DeriveSessionCookieName(%q) = %q, want %q", tt.appName, got, tt.want)
			}
			if !isValidCookieTokenName(got) {
				t.Fatalf("DeriveSessionCookieName(%q) = %q, not a valid cookie token name", tt.appName, got)
			}
		})
	}
}

func isValidCookieTokenName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func TestGetString_Found(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	_ = sm.Set(r, "user", "alice")
	got, err := GetString(sm, r, "user")
	if err != nil {
		t.Fatalf("GetString: %v", err)
	}
	if got != "alice" {
		t.Errorf("GetString = %q, want alice", got)
	}
}

func TestGetString_NotFound(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	_, err := GetString(sm, r, "missing")
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
	r := testRequest()
	_ = sm.Set(r, "user", 123)
	_, err := GetString(sm, r, "user")
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
	r := testRequest()
	_ = sm.Set(r, "count", 42)
	got, err := GetInt(sm, r, "count")
	if err != nil {
		t.Fatalf("GetInt: %v", err)
	}
	if got != 42 {
		t.Errorf("GetInt = %d, want 42", got)
	}
}

func TestGetInt_NotFound(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	_, err := GetInt(sm, r, "missing")
	if err == nil {
		t.Fatal("GetInt(missing) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetInt(missing): not SessionError: %v", err)
	}
}

func TestGetInt_InvalidType(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	_ = sm.Set(r, "count", "not-an-int")
	_, err := GetInt(sm, r, "count")
	if err == nil {
		t.Fatal("GetInt(string) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetInt(string): not SessionError: %v", err)
	}
}

func TestGetBool_Found(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	_ = sm.Set(r, "ok", true)
	got, err := GetBool(sm, r, "ok")
	if err != nil {
		t.Fatalf("GetBool: %v", err)
	}
	if !got {
		t.Error("GetBool = false, want true")
	}
}

func TestGetBool_NotFound(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	_, err := GetBool(sm, r, "missing")
	if err == nil {
		t.Fatal("GetBool(missing) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetBool(missing): not SessionError: %v", err)
	}
}

func TestGetBool_InvalidType(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	_ = sm.Set(r, "ok", "yes")
	_, err := GetBool(sm, r, "ok")
	if err == nil {
		t.Fatal("GetBool(string) = nil error, want SessionError")
	}
	if !IsSessionError(err) {
		t.Errorf("GetBool(string): not SessionError: %v", err)
	}
}

func TestSaveSessionValueClaims_NilValueClaims(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	err := SaveSessionValueClaims(sm, r, map[string]any{"roles": []string{"admin"}}, nil)
	if err != nil {
		t.Errorf("SaveSessionValueClaims(nil valueClaims) = %v", err)
	}
	_, err = GetString(sm, r, "roles")
	if err == nil {
		t.Error("expected no session key set")
	}
}

func TestSaveSessionValueClaims_StringClaim(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	claims := map[string]any{"email": "a@b.com"}
	valueClaims := map[string]string{"email": "email"}
	err := SaveSessionValueClaims(sm, r, claims, valueClaims)
	if err != nil {
		t.Fatalf("SaveSessionValueClaims: %v", err)
	}
	got, err := GetString(sm, r, "email")
	if err != nil {
		t.Fatalf("GetString: %v", err)
	}
	if got != "a@b.com" {
		t.Errorf("email = %q, want a@b.com", got)
	}
}

func TestSaveSessionValueClaims_SliceClaimNormalized(t *testing.T) {
	sm := newMapSessionManager()
	r := testRequest()
	claims := map[string]any{"roles": []any{"admin", "user"}}
	valueClaims := map[string]string{"roles": "roles"}
	err := SaveSessionValueClaims(sm, r, claims, valueClaims)
	if err != nil {
		t.Fatalf("SaveSessionValueClaims: %v", err)
	}
	val, _ := sm.Get(r, "roles")
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
	r := testRequest()
	claims := map[string]any{"email": "a@b.com"}
	valueClaims := map[string]string{"roles": "roles"}
	err := SaveSessionValueClaims(sm, r, claims, valueClaims)
	if err != nil {
		t.Fatalf("SaveSessionValueClaims: %v", err)
	}
	_, err = GetString(sm, r, "roles")
	if err == nil {
		t.Error("roles should not be set when claim missing")
	}
}

func TestSaveSessionValueClaims_SetFails(t *testing.T) {
	fail := &failingSessionManager{data: make(map[string]any)}
	r := testRequest()
	claims := map[string]any{"email": "a@b.com"}
	valueClaims := map[string]string{"email": "email"}
	err := SaveSessionValueClaims(fail, r, claims, valueClaims)
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
	r := testRequest()
	_ = sm.Set(r, "user", "alice")
	_ = sm.ClearInvalidate(r)
	_, err := GetString(sm, r, "user")
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	var testErr error
	handler := scsMgr.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set
		if err := mgr.Set(r, "key1", "value1"); err != nil {
			testErr = fmt.Errorf("Set: %w", err)
			return
		}

		// Get
		val, err := mgr.Get(r, "key1")
		if err != nil {
			testErr = fmt.Errorf("Get: %w", err)
			return
		}
		if val != "value1" {
			testErr = fmt.Errorf("Get = %v, want value1", val)
			return
		}

		// Delete
		if err := mgr.Delete(r, "key1"); err != nil {
			testErr = fmt.Errorf("Delete: %w", err)
			return
		}
		val, _ = mgr.Get(r, "key1")
		if val != nil {
			testErr = fmt.Errorf("Get after Delete = %v, want nil", val)
			return
		}

		// Set again, then Clear
		_ = mgr.Set(r, "a", "1")
		_ = mgr.Set(r, "b", "2")
		if err := mgr.Clear(r); err != nil {
			testErr = fmt.Errorf("Clear: %w", err)
			return
		}
		v, _ := mgr.Get(r, "a")
		if v != nil {
			testErr = fmt.Errorf("Get after Clear = %v, want nil", v)
			return
		}

		// Invalidate
		_ = mgr.Set(r, "x", "y")
		if err := mgr.Invalidate(r); err != nil {
			testErr = fmt.Errorf("Invalidate: %w", err)
			return
		}

		// ClearInvalidate
		_ = mgr.Set(r, "z", "w")
		if err := mgr.ClearInvalidate(r); err != nil {
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	var testErr error
	handler := scsMgr.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = mgr.Set(r, "user", "alice")
		if err := mgr.RenewToken(r); err != nil {
			testErr = fmt.Errorf("RenewToken: %w", err)
			return
		}
		// Verify data survives renewal
		val, err := mgr.Get(r, "user")
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

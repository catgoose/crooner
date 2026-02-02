package crooner

import (
	"errors"
	"net/http"
	"net/http/httptest"
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

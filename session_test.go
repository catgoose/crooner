package crooner

import (
	"net/http"
	"net/http/httptest"
	"testing"

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

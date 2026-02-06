package crooner

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

func minimalAuthHandlerConfig(sm SessionManager) *AuthHandlerConfig {
	return &AuthHandlerConfig{
		SessionMgr: sm,
		AuthConfig: &AuthConfig{
			OAuth2Config: &oauth2.Config{
				ClientID:    "client-id",
				RedirectURL: "https://example.com/callback",
				Endpoint:    microsoft.AzureADEndpoint("00000000-0000-0000-0000-000000000000"),
			},
			AuthRoutes:        &AuthRoutes{Login: "/login", Callback: "/callback", Logout: "/logout"},
			TenantID:          "00000000-0000-0000-0000-000000000000",
			LogoutURLRedirect: "https://example.com/logout",
			LoginURLRedirect:  "https://example.com/",
			URLValidation:     nil,
			ErrorConfig:       nil,
			SecurityHeaders:   nil,
			UserClaim:         "email",
		},
	}
}

func TestHandleError_NoShowDetails(t *testing.T) {
	a := minimalAuthHandlerConfig(newMapSessionManager())
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := a.handleError(c, 500, "test message", errors.New("underlying"))
	if err != nil {
		t.Fatalf("handleError: %v", err)
	}
	if rec.Code != 500 {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var resp ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if resp.Title != "test message" {
		t.Errorf("Title = %q", resp.Title)
	}
	if resp.Status != 500 {
		t.Errorf("Status = %d", resp.Status)
	}
	if resp.Detail != "test message" {
		t.Errorf("Detail = %q", resp.Detail)
	}
	if resp.Type != "about:blank" {
		t.Errorf("Type = %q, want about:blank", resp.Type)
	}
}

func TestHandleError_ShowDetails(t *testing.T) {
	a := minimalAuthHandlerConfig(newMapSessionManager())
	a.ErrorConfig = &ErrorConfig{ShowDetails: true}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	underlying := errors.New("underlying error")
	err := a.handleError(c, 400, "bad request", underlying)
	if err != nil {
		t.Fatalf("handleError: %v", err)
	}
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var resp ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if resp.Title != "bad request" {
		t.Errorf("Title = %q", resp.Title)
	}
	if resp.Detail != "underlying error" {
		t.Errorf("Detail = %q", resp.Detail)
	}
}

func TestHandleError_SessionError_SetsTypeAndExtensions(t *testing.T) {
	a := minimalAuthHandlerConfig(newMapSessionManager())
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := a.handleError(c, 400, "Code verifier not found", &SessionError{Key: "code_verifier", Reason: ReasonNotFound})
	if err != nil {
		t.Fatalf("handleError: %v", err)
	}
	var resp ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if resp.Type != problemTypeSession {
		t.Errorf("Type = %q, want %q", resp.Type, problemTypeSession)
	}
	if resp.Key != "code_verifier" {
		t.Errorf("Key = %q", resp.Key)
	}
	if resp.Reason != ReasonNotFound {
		t.Errorf("Reason = %q", resp.Reason)
	}
}

func TestLoginHandler_ValidRedirect_StoresStateAndRedirects(t *testing.T) {
	sm := newMapSessionManager()
	a := minimalAuthHandlerConfig(sm)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/login?redirect=/dashboard", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/login")
	_ = a.loginHandler()(c)

	if rec.Code != 307 {
		t.Errorf("status = %d, want 307", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("Location empty")
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Parse Location: %v", err)
	}
	q := parsed.Query()
	if q.Get("state") == "" {
		t.Error("state missing in redirect URL")
	}
	if q.Get("code_challenge") == "" {
		t.Error("code_challenge missing in redirect URL")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Error("code_challenge_method not S256")
	}
	if q.Get("nonce") == "" {
		t.Error("nonce missing in redirect URL")
	}

	state, err := GetString(sm, c, SessionKeyOAuthState)
	if err != nil || state == "" {
		t.Errorf("session oauth_state: %v", err)
	}
	verifier, err := GetString(sm, c, SessionKeyCodeVerifier)
	if err != nil || verifier == "" {
		t.Errorf("session code_verifier: %v", err)
	}
	nonce, err := GetString(sm, c, SessionKeyOAuthNonce)
	if err != nil || nonce == "" {
		t.Errorf("session oauth_nonce: %v", err)
	}

	decodedPath, err := DecodeStatePayload(state)
	if err != nil {
		t.Fatalf("DecodeStatePayload: %v", err)
	}
	if decodedPath != "/dashboard" {
		t.Errorf("decoded path = %q, want /dashboard", decodedPath)
	}
}

func TestLoginHandler_InvalidRedirect_RedirectsToSafeTarget(t *testing.T) {
	sm := newMapSessionManager()
	a := minimalAuthHandlerConfig(sm)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/login?redirect=//evil.com", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/login")
	_ = a.loginHandler()(c)

	if rec.Code != 302 {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "https://example.com/" {
		t.Errorf("Location = %q, want https://example.com/", loc)
	}
}

func TestLoginHandler_NoLoginURLRedirect_RedirectsToSlash(t *testing.T) {
	sm := newMapSessionManager()
	a := minimalAuthHandlerConfig(sm)
	a.LoginURLRedirect = ""
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/login?redirect=//evil.com", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/login")
	_ = a.loginHandler()(c)

	if rec.Code != 302 {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "/" {
		t.Errorf("Location = %q, want /", rec.Header().Get("Location"))
	}
}

func TestLoginHandler_InvalidRedirect_AbsoluteURL_RedirectsToSafeTarget(t *testing.T) {
	sm := newMapSessionManager()
	a := minimalAuthHandlerConfig(sm)
	a.LoginURLRedirect = "https://example.com/landing"
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/login?redirect=https://evil.com/path", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/login")
	_ = a.loginHandler()(c)

	if rec.Code != 302 {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "https://example.com/landing" {
		t.Errorf("Location = %q, want https://example.com/landing", rec.Header().Get("Location"))
	}
	_, err := GetString(sm, c, SessionKeyOAuthState)
	if err == nil {
		t.Error("invalid redirect should not store oauth_state in session")
	}
}

func TestCallbackHandler_NoStateInSession_500(t *testing.T) {
	sm := newMapSessionManager()
	a := minimalAuthHandlerConfig(sm)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/callback?state=anything&code=abc", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/callback")
	_ = a.callbackHandler()(c)

	if rec.Code != 500 {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	var resp ProblemDetails
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Title != "Session error" {
		t.Errorf("Title = %q", resp.Title)
	}
	if resp.Detail != "Failed to get session" {
		t.Errorf("Detail = %q", resp.Detail)
	}
}

func TestCallbackHandler_StateMismatch_RedirectToLogin(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	stateVal := EncodeStatePayload("csrf123", "/dashboard")
	_ = sm.Set(c, SessionKeyOAuthState, stateVal)
	_ = sm.Set(c, SessionKeyCodeVerifier, "verifier")

	e := echo.New()
	a := minimalAuthHandlerConfig(sm)
	req := httptest.NewRequest(http.MethodGet, "/callback?state=wrongstate&code=abc", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/callback")
	_ = a.callbackHandler()(ctx)

	if rec.Code != 302 {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?redirect=") {
		t.Errorf("Location = %q", loc)
	}
}

func TestCallbackHandler_InvalidStatePayload_RedirectToLoginURLRedirect(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	malformed := base64.StdEncoding.EncodeToString([]byte("nopipe"))
	_ = sm.Set(c, SessionKeyOAuthState, malformed)
	_ = sm.Set(c, SessionKeyCodeVerifier, "v")

	e := echo.New()
	a := minimalAuthHandlerConfig(sm)
	a.LoginURLRedirect = "https://example.com/landing"
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+malformed+"&code=abc", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/callback")
	_ = a.callbackHandler()(ctx)

	if rec.Code != 302 {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "https://example.com/landing" {
		t.Errorf("Location = %q", rec.Header().Get("Location"))
	}
}

func TestCallbackHandler_NoCodeVerifier_400(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	stateVal := EncodeStatePayload("csrf123", "/dashboard")
	_ = sm.Set(c, SessionKeyOAuthState, stateVal)

	e := echo.New()
	a := minimalAuthHandlerConfig(sm)
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+stateVal+"&code=abc", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/callback")
	_ = a.callbackHandler()(ctx)

	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var resp ProblemDetails
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Title != "Session error" {
		t.Errorf("Title = %q", resp.Title)
	}
	if resp.Detail != "Code verifier not found" {
		t.Errorf("Detail = %q", resp.Detail)
	}
}

func TestCallbackHandler_EmptyCode_400(t *testing.T) {
	sm := newMapSessionManager()
	c := echoContext()
	stateVal := EncodeStatePayload("csrf123", "/dashboard")
	_ = sm.Set(c, SessionKeyOAuthState, stateVal)
	_ = sm.Set(c, SessionKeyCodeVerifier, "verifier")

	e := echo.New()
	a := minimalAuthHandlerConfig(sm)
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+stateVal, nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/callback")
	_ = a.callbackHandler()(ctx)

	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var resp ProblemDetails
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Type != problemTypeInvalidRequest {
		t.Errorf("Type = %q, want %q", resp.Type, problemTypeInvalidRequest)
	}
	if resp.Title != "Invalid request" {
		t.Errorf("Title = %q", resp.Title)
	}
	if resp.Detail != "Authorization code not provided" {
		t.Errorf("Detail = %q", resp.Detail)
	}
}

func TestLogoutHandler_InvalidRedirectURL_400(t *testing.T) {
	sm := newMapSessionManager()
	a := minimalAuthHandlerConfig(sm)
	a.LogoutURLRedirect = "not-a-url"

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/logout")
	_ = a.logoutHandler()(c)

	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var resp ProblemDetails
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Title != "Invalid redirect URL" {
		t.Errorf("Title = %q", resp.Title)
	}
}

func TestLogoutHandler_Success_RedirectsToMicrosoftLogout(t *testing.T) {
	sm := newMapSessionManager()
	a := minimalAuthHandlerConfig(sm)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/logout")
	_ = a.logoutHandler()(c)

	if rec.Code != 302 {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	expectedPrefix := "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/logout?post_logout_redirect_uri="
	if !strings.HasPrefix(loc, expectedPrefix) {
		t.Errorf("Location = %q", loc)
	}
	parsed, _ := url.Parse(loc)
	if parsed.Query().Get("post_logout_redirect_uri") != "https://example.com/logout" {
		t.Errorf("post_logout_redirect_uri = %q", parsed.Query().Get("post_logout_redirect_uri"))
	}
}

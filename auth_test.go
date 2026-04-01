package crooner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestValidateRedirectURL_ValidURL_NilConfig(t *testing.T) {
	if err := ValidateRedirectURL("https://example.com/callback", nil); err != nil {
		t.Errorf("ValidateRedirectURL(valid, nil) = %v, want nil", err)
	}
	if err := ValidateRedirectURL("http://localhost:8080/callback", nil); err != nil {
		t.Errorf("ValidateRedirectURL(http localhost, nil) = %v, want nil", err)
	}
}

func TestValidateRedirectURL_InvalidFormat(t *testing.T) {
	if err := ValidateRedirectURL("not-a-url", nil); err == nil {
		t.Error("ValidateRedirectURL(not-a-url, nil) = nil, want error")
	}
	if err := ValidateRedirectURL("ftp://example.com", nil); err == nil {
		t.Error("ValidateRedirectURL(ftp, nil) = nil, want error")
	}
}

func TestValidateRedirectURL_RequireHTTPS(t *testing.T) {
	uv := &URLValidationConfig{RequireHTTPS: true}
	if err := ValidateRedirectURL("https://example.com", uv); err != nil {
		t.Errorf("ValidateRedirectURL(https, RequireHTTPS) = %v, want nil", err)
	}
	if err := ValidateRedirectURL("http://example.com", uv); err == nil {
		t.Error("ValidateRedirectURL(http, RequireHTTPS) = nil, want error")
	}
}

func TestValidateRedirectURL_AllowedSchemes(t *testing.T) {
	uv := &URLValidationConfig{AllowedSchemes: []string{"https"}}
	if err := ValidateRedirectURL("https://example.com", uv); err != nil {
		t.Errorf("ValidateRedirectURL(https) = %v, want nil", err)
	}
	if err := ValidateRedirectURL("http://example.com", uv); err == nil {
		t.Error("ValidateRedirectURL(http) = nil, want error")
	}
}

func TestValidateRedirectURL_AllowedDomains(t *testing.T) {
	uv := &URLValidationConfig{AllowedDomains: []string{"example.com"}}
	if err := ValidateRedirectURL("https://example.com/callback", uv); err != nil {
		t.Errorf("ValidateRedirectURL(example.com) = %v, want nil", err)
	}
	if err := ValidateRedirectURL("https://sub.example.com/callback", uv); err != nil {
		t.Errorf("ValidateRedirectURL(sub.example.com) = %v, want nil", err)
	}
	if err := ValidateRedirectURL("https://evil.com/callback", uv); err == nil {
		t.Error("ValidateRedirectURL(evil.com) = nil, want error")
	}
}

func TestIsAuthExemptPath_NilRoutes(t *testing.T) {
	if IsAuthExemptPath("/login", nil) {
		t.Error("IsAuthExemptPath(..., nil) = true, want false")
	}
}

func TestIsAuthExemptPath_LoginCallbackLogout(t *testing.T) {
	routes := &AuthRoutes{Login: "/login", Callback: "/callback", Logout: "/logout"}
	for _, path := range []string{"/login", "/login?redirect=/", "/callback", "/callback?code=x", "/logout"} {
		if !IsAuthExemptPath(path, routes) {
			t.Errorf("IsAuthExemptPath(%q) = false, want true", path)
		}
	}
	if IsAuthExemptPath("/dashboard", routes) {
		t.Error("IsAuthExemptPath(/dashboard) = true, want false")
	}
}

func TestIsAuthExemptPath_AuthExempt(t *testing.T) {
	routes := &AuthRoutes{
		Login: "/login", Callback: "/callback", Logout: "/logout",
		AuthExempt: []string{"/health", "/public"},
	}
	for _, path := range []string{"/health", "/health/ready", "/public", "/public/static"} {
		if !IsAuthExemptPath(path, routes) {
			t.Errorf("IsAuthExemptPath(%q) = false, want true", path)
		}
	}
	if IsAuthExemptPath("/private", routes) {
		t.Error("IsAuthExemptPath(/private) = true, want false")
	}
}

func TestValidatePostLoginRedirect_RelativePaths(t *testing.T) {
	base := "https://example.com"
	for _, tc := range []struct {
		path     string
		wantPath string
		wantErr  bool
	}{
		{"/", "/", false},
		{"/dashboard", "/dashboard", false},
		{"/dashboard?id=42", "/dashboard?id=42", false},
		{"/foo/bar", "/foo/bar", false},
		{"/foo/../bar", "/bar", false},
		{"/foo/./bar", "/foo/bar", false},
		{"", "/", false},
	} {
		got, err := ValidatePostLoginRedirect(tc.path, base, nil)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ValidatePostLoginRedirect(%q) = %q, nil; want error", tc.path, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidatePostLoginRedirect(%q) = %q, %v; want %q, nil", tc.path, got, err, tc.wantPath)
			continue
		}
		if tc.path != "" && tc.path != "/foo/../bar" && tc.path != "/foo/./bar" {
			if got != tc.wantPath {
				t.Errorf("ValidatePostLoginRedirect(%q) = %q; want %q", tc.path, got, tc.wantPath)
			}
		}
		if tc.path == "" && got != "/" {
			t.Errorf("ValidatePostLoginRedirect(%q) = %q; want /", tc.path, got)
		}
		if tc.path == "/foo/../bar" && got != "/bar" {
			t.Errorf("ValidatePostLoginRedirect(/foo/../bar) = %q; want /bar", got)
		}
		if tc.path == "/foo/./bar" && got != "/foo/bar" {
			t.Errorf("ValidatePostLoginRedirect(/foo/./bar) = %q; want /foo/bar", got)
		}
	}
}

func TestValidatePostLoginRedirect_Rejected(t *testing.T) {
	base := "https://example.com"
	for _, path := range []string{
		"//evil.com/path",
		"//evil.com",
		"https://evil.com/path",
		"http://evil.com",
		"javascript:alert(1)",
		"relative/no/leading/slash",
	} {
		got, err := ValidatePostLoginRedirect(path, base, nil)
		if err == nil {
			t.Errorf("ValidatePostLoginRedirect(%q) = %q, nil; want error", path, got)
		}
	}
}

func TestAuthError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("inner")
	ae := &AuthError{Op: "TestOp", Reason: "test reason", Err: inner}
	if ae.Error() == "" {
		t.Error("AuthError.Error() empty")
	}
	if !strings.Contains(ae.Error(), "TestOp") || !strings.Contains(ae.Error(), "test reason") {
		t.Errorf("AuthError.Error() = %q", ae.Error())
	}
	if ae.Unwrap() != inner {
		t.Error("AuthError.Unwrap() != inner")
	}
	aeNoErr := &AuthError{Op: "Op", Reason: "reason", Err: nil}
	if aeNoErr.Error() == "" {
		t.Error("AuthError with nil Err: Error() empty")
	}
	if aeNoErr.Unwrap() != nil {
		t.Error("AuthError with nil Err: Unwrap() != nil")
	}
}

func TestAuthError_IsAuthError_AsAuthError(t *testing.T) {
	ae := &AuthError{Op: "Op", Reason: "reason", Err: nil}
	if !IsAuthError(ae) {
		t.Error("IsAuthError(AuthError) = false")
	}
	got, ok := AsAuthError(ae)
	if !ok || got != ae {
		t.Errorf("AsAuthError = %v, %v; want ae, true", got, ok)
	}
	if IsAuthError(nil) {
		t.Error("IsAuthError(nil) = true")
	}
	_, ok = AsAuthError(nil)
	if ok {
		t.Error("AsAuthError(nil) = true")
	}
	wrapped := errors.Join(ae, errors.New("other"))
	if !IsAuthError(wrapped) {
		t.Error("IsAuthError(wrapped AuthError) = false")
	}
	got, ok = AsAuthError(wrapped)
	if !ok || got != ae {
		t.Errorf("AsAuthError(wrapped) = %v, %v", got, ok)
	}
}

func TestConfigError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("inner")
	ce := &ConfigError{Field: "Field", Reason: "reason", Err: inner}
	if ce.Error() == "" {
		t.Error("ConfigError.Error() empty")
	}
	if !strings.Contains(ce.Error(), "Field") || !strings.Contains(ce.Error(), "reason") {
		t.Errorf("ConfigError.Error() = %q", ce.Error())
	}
	if ce.Unwrap() != inner {
		t.Error("ConfigError.Unwrap() != inner")
	}
	ceNoErr := &ConfigError{Field: "F", Reason: "r", Err: nil}
	if ceNoErr.Unwrap() != nil {
		t.Error("ConfigError with nil Err: Unwrap() != nil")
	}
}

func TestConfigError_IsConfigError_AsConfigError(t *testing.T) {
	ce := &ConfigError{Field: "F", Reason: "r", Err: nil}
	if !IsConfigError(ce) {
		t.Error("IsConfigError(ConfigError) = false")
	}
	got, ok := AsConfigError(ce)
	if !ok || got != ce {
		t.Errorf("AsConfigError = %v, %v; want ce, true", got, ok)
	}
	if IsConfigError(nil) {
		t.Error("IsConfigError(nil) = true")
	}
	_, ok = AsConfigError(nil)
	if ok {
		t.Error("AsConfigError(nil) = true")
	}
}

func validAuthConfigParams() *AuthConfigParams {
	return &AuthConfigParams{
		IssuerURL:          "https://accounts.example.com",
		ClientID:           "my-client-id",
		RedirectURL:        "https://example.com/callback",
		LogoutURLRedirect:  "https://example.com/logout",
		LoginURLRedirect:   "https://example.com/",
		AuthRoutes:         &AuthRoutes{Login: "/login", Callback: "/callback", Logout: "/logout"},
		URLValidation:      nil,
		SessionMgr:         nil,
		SecurityHeaders:    nil,
		ErrorConfig:        nil,
		SessionSecurity:    nil,
		CookieName:         "",
		UserClaim:          "",
		AdditionalScopes:   nil,
		SessionValueClaims: nil,
	}
}

func TestNewAuthConfig_MissingIssuerURL(t *testing.T) {
	params := validAuthConfigParams()
	params.IssuerURL = ""
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(missing IssuerURL) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "IssuerURL" || ce.Reason != "missing required parameter" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_MissingClientID(t *testing.T) {
	params := validAuthConfigParams()
	params.ClientID = ""
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(missing ClientID) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "ClientID" || ce.Reason != "missing required parameter" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_MissingRedirectURL(t *testing.T) {
	params := validAuthConfigParams()
	params.RedirectURL = ""
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(missing RedirectURL) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "RedirectURL" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_InvalidRedirectURL(t *testing.T) {
	params := validAuthConfigParams()
	params.RedirectURL = "not-a-url"
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(invalid RedirectURL) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "RedirectURL" || ce.Reason != "invalid URL" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_MissingLogoutURLRedirect(t *testing.T) {
	params := validAuthConfigParams()
	params.LogoutURLRedirect = ""
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(missing LogoutURLRedirect) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "LogoutURLRedirect" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_MissingLoginURLRedirect(t *testing.T) {
	params := validAuthConfigParams()
	params.LoginURLRedirect = ""
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(missing LoginURLRedirect) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "LoginURLRedirect" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_MissingAuthRoutes(t *testing.T) {
	params := validAuthConfigParams()
	params.AuthRoutes = nil
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(nil AuthRoutes) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "AuthRoutes" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_EmptyAuthRoutes(t *testing.T) {
	params := validAuthConfigParams()
	params.AuthRoutes = &AuthRoutes{Login: "", Callback: "/callback", Logout: "/logout"}
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(empty Login) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "AuthRoutes" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_InvalidAdditionalScopes(t *testing.T) {
	params := validAuthConfigParams()
	params.AdditionalScopes = []string{"openid", " ", "email"}
	mux := http.NewServeMux()
	_, err := NewAuthConfig(context.Background(), mux, params)
	if err == nil {
		t.Fatal("NewAuthConfig(empty scope) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "AdditionalScopes[1]" || ce.Reason != "scope cannot be empty" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestGetLoginURL_ContainsParams(t *testing.T) {
	cfg := &AuthConfig{
		OAuth2Config: &oauth2.Config{
			ClientID:    "client-id",
			RedirectURL: "https://example.com/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://example.com/authorize", TokenURL: "https://example.com/token"},
		},
	}
	state := "my-state"
	challenge := "my-challenge"
	urlStr := cfg.GetLoginURL(state, challenge, "")
	if urlStr == "" {
		t.Fatal("GetLoginURL returned empty")
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		t.Fatalf("Parse URL: %v", err)
	}
	q := parsed.Query()
	if q.Get("state") != state {
		t.Errorf("state = %q, want %q", q.Get("state"), state)
	}
	if q.Get("code_challenge") != challenge {
		t.Errorf("code_challenge = %q, want %q", q.Get("code_challenge"), challenge)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("nonce") != "" {
		t.Errorf("nonce = %q, want empty", q.Get("nonce"))
	}
}

func TestGetLoginURL_WithNonce(t *testing.T) {
	cfg := &AuthConfig{
		OAuth2Config: &oauth2.Config{
			ClientID:    "client-id",
			RedirectURL: "https://example.com/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://example.com/authorize", TokenURL: "https://example.com/token"},
		},
	}
	nonce := "my-nonce"
	urlStr := cfg.GetLoginURL("state", "challenge", nonce)
	parsed, err := url.Parse(urlStr)
	if err != nil {
		t.Fatalf("Parse URL: %v", err)
	}
	if parsed.Query().Get("nonce") != nonce {
		t.Errorf("nonce = %q, want %q", parsed.Query().Get("nonce"), nonce)
	}
}

func TestFetchOIDCDiscovery_Success(t *testing.T) {
	discovery := `{
		"issuer": "http://localhost",
		"authorization_endpoint": "http://localhost/authorize",
		"token_endpoint": "http://localhost/token",
		"end_session_endpoint": "http://localhost/logout",
		"jwks_uri": "http://localhost/jwks",
		"response_types_supported": ["code"],
		"scopes_supported": ["openid"]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(discovery))
	}))
	defer srv.Close()

	d, err := fetchOIDCDiscovery(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchOIDCDiscovery: %v", err)
	}
	if d.AuthorizationEndpoint != "http://localhost/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", d.AuthorizationEndpoint)
	}
	if d.TokenEndpoint != "http://localhost/token" {
		t.Errorf("TokenEndpoint = %q", d.TokenEndpoint)
	}
	if d.EndSessionEndpoint != "http://localhost/logout" {
		t.Errorf("EndSessionEndpoint = %q", d.EndSessionEndpoint)
	}
}

func TestFetchOIDCDiscovery_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchOIDCDiscovery(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("fetchOIDCDiscovery with 500 = nil error")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("err = %v, want status 500 mention", err)
	}
}

func TestFetchOIDCDiscovery_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := fetchOIDCDiscovery(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("fetchOIDCDiscovery with bad JSON = nil error")
	}
}

func TestFetchOIDCDiscovery_MissingEndpoints(t *testing.T) {
	discovery := `{
		"issuer": "http://localhost",
		"jwks_uri": "http://localhost/jwks"
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(discovery))
	}))
	defer srv.Close()

	_, err := fetchOIDCDiscovery(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("fetchOIDCDiscovery with missing endpoints = nil error")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("err = %v, want 'missing' mention", err)
	}
}

func TestGetDefaultSessionSecurity(t *testing.T) {
	ss := getDefaultSessionSecurity()
	if ss == nil {
		t.Fatal("getDefaultSessionSecurity() = nil")
	}
	if !ss.HTTPOnly {
		t.Error("HTTPOnly = false, want true")
	}
	if !ss.Secure {
		t.Error("Secure = false, want true")
	}
	if ss.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want LaxMode", ss.SameSite)
	}
	if ss.MaxAge != 3600 {
		t.Errorf("MaxAge = %d, want 3600", ss.MaxAge)
	}
	if ss.Path != "/" {
		t.Errorf("Path = %q, want /", ss.Path)
	}
}

package crooner

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
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
		TenantID:           "00000000-0000-0000-0000-000000000000",
		ClientID:           "11111111-1111-1111-1111-111111111111",
		ClientSecret:       "secret",
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

func TestNewAuthConfig_MissingTenantID(t *testing.T) {
	params := validAuthConfigParams()
	params.TenantID = ""
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
	if err == nil {
		t.Fatal("NewAuthConfig(missing TenantID) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "TenantID" || ce.Reason != "missing required parameter" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_InvalidTenantID_NotUUID(t *testing.T) {
	params := validAuthConfigParams()
	params.TenantID = "not-a-uuid"
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
	if err == nil {
		t.Fatal("NewAuthConfig(invalid TenantID) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "TenantID" || ce.Reason != "invalid UUID format" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_InvalidTenantID_WrongLength(t *testing.T) {
	params := validAuthConfigParams()
	params.TenantID = "00000000-0000-0000-0000-00000000000"
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
	if err == nil {
		t.Fatal("NewAuthConfig(TenantID wrong length) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "TenantID" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_InvalidTenantID_InvalidChars(t *testing.T) {
	params := validAuthConfigParams()
	params.TenantID = "00000000-0000-0000-0000-00000000000x"
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
	if err == nil {
		t.Fatal("NewAuthConfig(TenantID invalid chars) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "TenantID" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_MissingClientID(t *testing.T) {
	params := validAuthConfigParams()
	params.ClientID = ""
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
	if err == nil {
		t.Fatal("NewAuthConfig(missing ClientID) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "ClientID" || ce.Reason != "missing required parameter" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_InvalidClientID(t *testing.T) {
	params := validAuthConfigParams()
	params.ClientID = "not-a-uuid"
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
	if err == nil {
		t.Fatal("NewAuthConfig(invalid ClientID) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "ClientID" || ce.Reason != "invalid UUID format" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_MissingClientSecret(t *testing.T) {
	params := validAuthConfigParams()
	params.ClientSecret = ""
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
	if err == nil {
		t.Fatal("NewAuthConfig(missing ClientSecret) = nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Field != "ClientSecret" || ce.Reason != "missing required parameter" {
		t.Errorf("NewAuthConfig = %v", err)
	}
}

func TestNewAuthConfig_MissingRedirectURL(t *testing.T) {
	params := validAuthConfigParams()
	params.RedirectURL = ""
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
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
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
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
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
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
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
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
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
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
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
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
	e := echo.New()
	err := NewAuthConfig(context.Background(), e, params)
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
			Endpoint:    microsoft.AzureADEndpoint("00000000-0000-0000-0000-000000000000"),
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
			Endpoint:    microsoft.AzureADEndpoint("00000000-0000-0000-0000-000000000000"),
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

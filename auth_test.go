package crooner

import (
	"testing"
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

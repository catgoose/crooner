package crooner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// AuthError represents an error related to authentication or OIDC operations.
type AuthError struct {
	Err    error
	Op     string
	Reason string
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("auth error during %s: %s: %v", e.Op, e.Reason, e.Err)
	}
	return fmt.Sprintf("auth error during %s: %s", e.Op, e.Reason)
}

func (e *AuthError) Unwrap() error { return e.Err }

// ConfigError represents an error related to configuration loading or validation.
type ConfigError struct {
	Err    error
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("config error for field %q: %s: %v", e.Field, e.Reason, e.Err)
	}
	return fmt.Sprintf("config error for field %q: %s", e.Field, e.Reason)
}

func (e *ConfigError) Unwrap() error { return e.Err }

// IsAuthError checks if an error is an AuthError
func IsAuthError(err error) bool {
	var authErr *AuthError
	return errors.As(err, &authErr)
}

// AsAuthError attempts to convert an error to AuthError
func AsAuthError(err error) (*AuthError, bool) {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr, true
	}
	return nil, false
}

// IsConfigError checks if an error is a ConfigError
func IsConfigError(err error) bool {
	var configErr *ConfigError
	return errors.As(err, &configErr)
}

// AsConfigError attempts to convert an error to ConfigError
func AsConfigError(err error) (*ConfigError, bool) {
	var configErr *ConfigError
	if errors.As(err, &configErr) {
		return configErr, true
	}
	return nil, false
}

// SessionSecurityConfig contains session security configuration
type SessionSecurityConfig struct {
	Domain   string
	Path     string
	SameSite http.SameSite
	MaxAge   int
	HTTPOnly bool
	Secure   bool
}

// URLValidationConfig contains URL validation configuration
type URLValidationConfig struct {
	AllowedSchemes []string
	AllowedDomains []string
	RequireHTTPS   bool
}

// ErrorConfig contains error handling configuration
type ErrorConfig struct {
	LogLevel    string
	ShowDetails bool
}

// SecurityHeadersConfig contains configuration for security headers.
//
// All fields are optional. If a field is empty, a secure default will be used.
//
//	ContentSecurityPolicy:    default-src 'self'
//	XFrameOptions:            DENY
//	XContentTypeOptions:      nosniff
//	ReferrerPolicy:           strict-origin-when-cross-origin
//	XXSSProtection:           1; mode=block
//	StrictTransportSecurity:  (not set by default)
type SecurityHeadersConfig struct {
	ContentSecurityPolicy   string // Content-Security-Policy header
	XFrameOptions           string // X-Frame-Options header
	XContentTypeOptions     string // X-Content-Type-Options header
	ReferrerPolicy          string // Referrer-Policy header
	XXSSProtection          string // X-XSS-Protection header
	StrictTransportSecurity string // Strict-Transport-Security header (set only if HTTPS)
}

// AuthConfig is the runtime config built by NewAuthConfig; it holds OAuth2/OIDC and security settings.
type AuthConfig struct {
	OAuth2Config      *oauth2.Config         // OAuth2 configuration
	Provider          *oidc.Provider         // OIDC Provider for Azure AD
	Verifier          *oidc.IDTokenVerifier  // Verifier to verify ID tokens
	AuthRoutes        *AuthRoutes            // Routes for authentication
	TenantID          string                 // Azure AD Tenant ID
	LogoutURLRedirect string                 // URL to redirect after logout
	LoginURLRedirect  string                 // URL to redirect after login (fallback when state decode fails)
	CookieName        string                 // Reserved for custom SessionManager; built-in flow uses SessionManager.GetCookieName()
	SessionSecurity   *SessionSecurityConfig // Reserved for custom SessionManager; built-in flow uses SessionConfig
	URLValidation     *URLValidationConfig   // URL validation configuration
	ErrorConfig       *ErrorConfig           // Error handling configuration
	SecurityHeaders   *SecurityHeadersConfig // Security headers configuration
	UserClaim         string                 // Claim name for session user (default "email"); use "preferred_username" or "upn" if email absent
}

// AuthConfigParams is the input for NewAuthConfig; do not reuse as runtime config.
type AuthConfigParams struct {
	SessionMgr         SessionManager
	AuthRoutes         *AuthRoutes
	SecurityHeaders    *SecurityHeadersConfig
	ErrorConfig        *ErrorConfig
	URLValidation      *URLValidationConfig
	SessionSecurity    *SessionSecurityConfig
	LogoutURLRedirect  string
	CookieName         string
	LoginURLRedirect   string
	ClientID           string
	RedirectURL        string
	TenantID           string
	ClientSecret       string
	UserClaim          string
	AdditionalScopes   []string
	SessionValueClaims []map[string]string
}

// AuthRoutes contains the routes for authentication
type AuthRoutes struct {
	Login      string   // Login route
	Logout     string   // Logout route
	Callback   string   // Callback route for receiving authorization code
	AuthExempt []string // Routes to be exempt from auth
}

// IsAuthExemptPath reports whether path is an auth route or listed in AuthExempt (prefix match).
func IsAuthExemptPath(path string, routes *AuthRoutes) bool {
	if routes == nil {
		return false
	}
	if strings.HasPrefix(path, routes.Login) ||
		strings.HasPrefix(path, routes.Callback) ||
		strings.HasPrefix(path, routes.Logout) {
		return true
	}
	for _, route := range routes.AuthExempt {
		if strings.HasPrefix(path, route) {
			return true
		}
	}
	return false
}

// loginRedirectURL constructs a login URL with redirect parameter.
func loginRedirectURL(routes *AuthRoutes, uri string) string {
	return fmt.Sprintf("%s?redirect=%s", routes.Login, url.QueryEscape(uri))
}

// NewAuthConfig creates a new AuthConfig based on the provided parameters.
// Returns a ConfigError if any required parameter is missing or invalid.
//
// Example error handling:
//
//	err := crooner.NewAuthConfig(ctx, e, params)
//	if err != nil {
//	    var cfgErr *crooner.ConfigError
//	    if errors.As(err, &cfgErr) {
//	        log.Printf("Config error: %s", cfgErr)
//	    } else {
//	        log.Printf("Other error: %v", err)
//	    }
//	}
func NewAuthConfig(ctx context.Context, e *echo.Echo, params *AuthConfigParams) error {
	if err := validateAuthParams(params); err != nil {
		return err
	}

	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", params.TenantID))
	if err != nil {
		return &ConfigError{Field: "TenantID", Reason: "failed to initialize OIDC provider", Err: err}
	}

	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	scopes = append(scopes, params.AdditionalScopes...)

	if params.CookieName == "" {
		params.CookieName = "crooner-auth"
	}

	if params.SessionSecurity == nil {
		params.SessionSecurity = getDefaultSessionSecurity()
	}

	if params.SecurityHeaders == nil {
		params.SecurityHeaders = &SecurityHeadersConfig{
			ContentSecurityPolicy: "default-src 'self'",
		}
	}
	if params.UserClaim == "" {
		params.UserClaim = "email"
	}

	authConfig := &AuthConfig{
		OAuth2Config: &oauth2.Config{
			ClientID:     params.ClientID,
			ClientSecret: params.ClientSecret,
			Endpoint:     microsoft.AzureADEndpoint(params.TenantID),
			RedirectURL:  params.RedirectURL,
			Scopes:       scopes,
		},
		Provider:          provider,
		Verifier:          provider.Verifier(&oidc.Config{ClientID: params.ClientID}),
		TenantID:          params.TenantID,
		LogoutURLRedirect: params.LogoutURLRedirect,
		LoginURLRedirect:  params.LoginURLRedirect,
		AuthRoutes:        params.AuthRoutes,
		CookieName:        params.CookieName,
		SessionSecurity:   params.SessionSecurity,
		URLValidation:     params.URLValidation,
		ErrorConfig:       params.ErrorConfig,
		SecurityHeaders:   params.SecurityHeaders,
		UserClaim:         params.UserClaim,
	}
	authHandlerConfig := &AuthHandlerConfig{
		AuthConfig:         authConfig,
		SessionValueClaims: params.SessionValueClaims,
		SessionMgr:         params.SessionMgr,
	}
	authHandlerConfig.SetupAuth(e)
	return nil
}

// validateAuthParams ensures all necessary parameters are provided and valid.
// Returns a ConfigError if any parameter is missing or invalid.
func validateAuthParams(params *AuthConfigParams) error {
	if err := validateRequiredAuthParams(params); err != nil {
		return err
	}
	if err := validateRedirectURLParams(params); err != nil {
		return err
	}
	if err := validateAuthRoutes(params); err != nil {
		return err
	}
	if err := validateAdditionalScopes(params); err != nil {
		return err
	}
	return nil
}

func validateRequiredAuthParams(params *AuthConfigParams) error {
	if params.TenantID == "" {
		return &ConfigError{Field: "TenantID", Reason: "missing required parameter"}
	}
	if !isValidUUID(params.TenantID) {
		return &ConfigError{Field: "TenantID", Reason: "invalid UUID format"}
	}
	if params.ClientID == "" {
		return &ConfigError{Field: "ClientID", Reason: "missing required parameter"}
	}
	if !isValidUUID(params.ClientID) {
		return &ConfigError{Field: "ClientID", Reason: "invalid UUID format"}
	}
	if params.ClientSecret == "" {
		return &ConfigError{Field: "ClientSecret", Reason: "missing required parameter"}
	}
	return nil
}

func validateRedirectURLParams(params *AuthConfigParams) error {
	redirects := []struct {
		field string
		url   string
	}{
		{"RedirectURL", params.RedirectURL},
		{"LogoutURLRedirect", params.LogoutURLRedirect},
		{"LoginURLRedirect", params.LoginURLRedirect},
	}
	for _, r := range redirects {
		if r.url == "" {
			return &ConfigError{Field: r.field, Reason: "missing required parameter"}
		}
		if err := ValidateRedirectURL(r.url, params.URLValidation); err != nil {
			return &ConfigError{Field: r.field, Reason: "invalid URL", Err: err}
		}
	}
	return nil
}

func validateAuthRoutes(params *AuthConfigParams) error {
	if params.AuthRoutes == nil || params.AuthRoutes.Login == "" || params.AuthRoutes.Logout == "" || params.AuthRoutes.Callback == "" {
		return &ConfigError{Field: "AuthRoutes", Reason: "missing required auth routes: Login, Logout, Callback must be defined"}
	}
	return nil
}

func validateAdditionalScopes(params *AuthConfigParams) error {
	for i, scope := range params.AdditionalScopes {
		if strings.TrimSpace(scope) == "" {
			return &ConfigError{Field: fmt.Sprintf("AdditionalScopes[%d]", i), Reason: "scope cannot be empty"}
		}
	}
	return nil
}

// isValidUUID checks if a string is a valid UUID
func isValidUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}

	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		return false
	}

	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return false
	}

	validChars := "0123456789abcdefABCDEF"
	for _, part := range parts {
		for _, char := range part {
			if !strings.ContainsRune(validChars, char) {
				return false
			}
		}
	}

	return true
}

// validateURL validates URL format
func validateURL(urlStr string) error {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid URL format")
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme %s not allowed", parsed.Scheme)
	}

	return nil
}

// ValidateRedirectURL validates a redirect URL: format/scheme/host first (via validateURL), then optional URLValidationConfig (RequireHTTPS, AllowedSchemes, AllowedDomains).
func ValidateRedirectURL(rawURL string, uv *URLValidationConfig) error {
	if err := validateURL(rawURL); err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	parsedURL, _ := url.Parse(rawURL) // already validated
	if uv == nil {
		return nil
	}
	if uv.RequireHTTPS && parsedURL.Scheme != "https" {
		return fmt.Errorf("HTTPS required for redirect URLs")
	}
	if len(uv.AllowedSchemes) > 0 && !slices.Contains(uv.AllowedSchemes, parsedURL.Scheme) {
		return fmt.Errorf("scheme %s not allowed", parsedURL.Scheme)
	}
	if len(uv.AllowedDomains) > 0 {
		domainAllowed := false
		for _, domain := range uv.AllowedDomains {
			if parsedURL.Host == domain || strings.HasSuffix(parsedURL.Host, "."+domain) {
				domainAllowed = true
				break
			}
		}
		if !domainAllowed {
			return fmt.Errorf("domain %s not allowed", parsedURL.Host)
		}
	}
	return nil
}

// ValidatePostLoginRedirect validates the post-login redirect target (originalPath).
// It allows only same-origin relative paths: must start with "/" and not "//", and must not be an absolute URL.
// Path is normalized (path.Clean) to prevent traversal; the returned safePath should be used for the redirect.
// baseURL and config are reserved for future use (e.g. allowlisting absolute URLs).
func ValidatePostLoginRedirect(originalPath string, baseURL string, config *URLValidationConfig) (safePath string, err error) {
	if originalPath == "" {
		return "/", nil
	}
	if strings.HasPrefix(originalPath, "//") {
		return "", fmt.Errorf("protocol-relative URL not allowed")
	}
	if !strings.HasPrefix(originalPath, "/") {
		return "", fmt.Errorf("redirect must be a relative path")
	}
	if strings.Contains(originalPath, "://") {
		return "", fmt.Errorf("absolute URL not allowed")
	}
	normalized := path.Clean(originalPath)
	if normalized != "/" && !strings.HasPrefix(normalized, "/") {
		return "", fmt.Errorf("invalid path after normalization")
	}
	return normalized, nil
}

// getDefaultSessionSecurity returns secure default session configuration
func getDefaultSessionSecurity() *SessionSecurityConfig {
	return &SessionSecurityConfig{
		HTTPOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
		Path:     "/",
	}
}

// GetLoginURL constructs and returns the Azure AD login URL
func (c *AuthConfig) GetLoginURL(state, codeChallenge, nonce string) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	return c.OAuth2Config.AuthCodeURL(state, opts...)
}

// ExchangeToken exchanges the authorization code for an access token
func (c *AuthConfig) ExchangeToken(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return c.OAuth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
}

// VerifyIDToken verifies the provided ID token using the OIDC provider
func (c *AuthConfig) VerifyIDToken(ctx context.Context, idToken string) (map[string]any, error) {
	idTokenObj, err := c.Verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, &AuthError{Op: "VerifyIDToken", Reason: "failed to verify ID token", Err: err}
	}

	var claims map[string]any
	if err := idTokenObj.Claims(&claims); err != nil {
		return nil, &AuthError{Op: "VerifyIDToken", Reason: "failed to parse ID token claims", Err: err}
	}
	return claims, nil
}

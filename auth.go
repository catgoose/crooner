package crooner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// AuthError represents an error related to authentication or OIDC operations.
type AuthError struct {
	Op     string // Operation (e.g., "ExchangeToken", "VerifyIDToken")
	Reason string // Human-readable reason
	Err    error  // Underlying error, if any
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
	Field  string // The config field or env var involved
	Reason string // Human-readable reason
	Err    error  // Underlying error, if any
}

func (e *ConfigError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("config error for field %q: %s: %v", e.Field, e.Reason, e.Err)
	}
	return fmt.Sprintf("config error for field %q: %s", e.Field, e.Reason)
}

func (e *ConfigError) Unwrap() error { return e.Err }

// SessionSecurityConfig contains session security configuration
type SessionSecurityConfig struct {
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   int
	Domain   string
	Path     string
}

// URLValidationConfig contains URL validation configuration
type URLValidationConfig struct {
	AllowedSchemes []string
	AllowedDomains []string
	RequireHTTPS   bool
}

// ErrorConfig contains error handling configuration
type ErrorConfig struct {
	ShowDetails bool
	LogLevel    string
}

// SecurityHeadersConfig contains configuration for security headers
type SecurityHeadersConfig struct {
	ContentSecurityPolicy string
}

// Error constants for consistent error messages
const (
	ErrGenericAuth       = "Authentication error occurred"
	ErrInvalidState      = "Invalid authentication state"
	ErrTokenExchange     = "Token exchange failed"
	ErrTokenVerification = "Token verification failed"
	ErrSessionError      = "Session error occurred"
	ErrInvalidRedirect   = "Invalid redirect URL"
)

// AuthConfig contains the configuration for Azure AD authentication
type AuthConfig struct {
	OAuth2Config      *oauth2.Config         // OAuth2 configuration
	Provider          *oidc.Provider         // OIDC Provider for Azure AD
	Verifier          *oidc.IDTokenVerifier  // Verifier to verify ID tokens
	AuthRoutes        *AuthRoutes            // Routes for authentication
	TenantID          string                 // Azure AD Tenant ID
	LogoutURLRedirect string                 // URL to redirect after logout
	LoginURLRedirect  string                 // URL to redirect after login
	CookieName        string                 // Key for the session cookie
	SessionSecurity   *SessionSecurityConfig // Session security configuration
	URLValidation     *URLValidationConfig   // URL validation configuration
	ErrorConfig       *ErrorConfig           // Error handling configuration
	SecurityHeaders   *SecurityHeadersConfig // Security headers configuration
}

// AuthConfigParams contains the parameters needed to configure Azure AD authentication
type AuthConfigParams struct {
	ClientID           string                 // Azure AD Client ID
	ClientSecret       string                 // Azure AD Client Secret
	TenantID           string                 // Azure AD Tenant ID
	RedirectURL        string                 // URL to redirect after login
	LogoutURLRedirect  string                 // URL to redirect after logout
	LoginURLRedirect   string                 // URL to redirect after login
	AuthRoutes         *AuthRoutes            // Routes for authentication
	AdditionalScopes   []string               // Additional scopes to request during authentication
	SessionValueClaims []map[string]string    // Map of session values to claims to store in session.  Use c.get("value") to retrieve claim
	CookieName         string                 // Key for the session cookie
	SessionSecurity    *SessionSecurityConfig // Session security configuration
	URLValidation      *URLValidationConfig   // URL validation configuration
	ErrorConfig        *ErrorConfig           // Error handling configuration
	SecurityHeaders    *SecurityHeadersConfig // Security headers configuration
	SessionMgr         SessionManager         // Pluggable session manager (SCS, etc.)
}

// AuthRoutes contains the routes for authentication
type AuthRoutes struct {
	Login      string   // Login route
	Logout     string   // Logout route
	Callback   string   // Callback route for receiving authorization code
	AuthExempt []string // Routes to be exempt from auth
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
	if params.RedirectURL == "" {
		return &ConfigError{Field: "RedirectURL", Reason: "missing required parameter"}
	}
	if err := validateURL(params.RedirectURL); err != nil {
		return &ConfigError{Field: "RedirectURL", Reason: "invalid URL", Err: err}
	}
	if params.LogoutURLRedirect == "" {
		return &ConfigError{Field: "LogoutURLRedirect", Reason: "missing required parameter"}
	}
	if err := validateURL(params.LogoutURLRedirect); err != nil {
		return &ConfigError{Field: "LogoutURLRedirect", Reason: "invalid URL", Err: err}
	}
	if params.LoginURLRedirect == "" {
		return &ConfigError{Field: "LoginURLRedirect", Reason: "missing required parameter"}
	}
	if err := validateURL(params.LoginURLRedirect); err != nil {
		return &ConfigError{Field: "LoginURLRedirect", Reason: "invalid URL", Err: err}
	}
	if params.AuthRoutes == nil || params.AuthRoutes.Login == "" || params.AuthRoutes.Logout == "" || params.AuthRoutes.Callback == "" {
		return &ConfigError{Field: "AuthRoutes", Reason: "missing required auth routes: Login, Logout, Callback must be defined"}
	}
	// Validate AdditionalScopes (optional, but should be non-empty strings)
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

	// Simple UUID format validation (8-4-4-4-12)
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		return false
	}

	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return false
	}

	// Check if all characters are hexadecimal
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

	// Only allow HTTP and HTTPS schemes by default
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme %s not allowed", parsed.Scheme)
	}

	return nil
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
func (c *AuthConfig) GetLoginURL(state, codeChallenge string) string {
	return c.OAuth2Config.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
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

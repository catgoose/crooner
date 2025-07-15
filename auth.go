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

// NewAuthConfig creates a new AuthConfig based on the provided parameters
func NewAuthConfig(ctx context.Context, e *echo.Echo, params *AuthConfigParams) error {
	// Validate parameters (remove SessionStore check)
	if err := validateAuthParams(params); err != nil {
		return err
	}

	// Set up OIDC provider and OAuth2 configuration
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", params.TenantID))
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	scopes = append(scopes, params.AdditionalScopes...)

	if params.CookieName == "" {
		params.CookieName = "crooner-auth"
	}

	// Apply default session security if not provided
	if params.SessionSecurity == nil {
		params.SessionSecurity = getDefaultSessionSecurity()
	}

	// Apply default security headers if not provided
	if params.SecurityHeaders == nil {
		params.SecurityHeaders = &SecurityHeadersConfig{
			ContentSecurityPolicy: "default-src 'self'", // secure default
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

// validateAuthParams ensures all necessary parameters are provided
func validateAuthParams(params *AuthConfigParams) error {
	if params.TenantID == "" {
		return fmt.Errorf("missing required parameter: TenantID")
	}
	if params.ClientID == "" {
		return fmt.Errorf("missing required parameter: ClientID")
	}
	if params.ClientSecret == "" {
		return fmt.Errorf("missing required parameter: ClientSecret")
	}
	if params.RedirectURL == "" {
		return fmt.Errorf("missing required parameter: RedirectURL")
	}
	if params.AuthRoutes == nil || params.AuthRoutes.Login == "" || params.AuthRoutes.Logout == "" || params.AuthRoutes.Callback == "" {
		return fmt.Errorf("missing required auth routes: Login, Logout, Callback, and Redirect routes must be defined")
	}
	// No SessionStore check

	// Validate TenantID format (UUID)
	if !isValidUUID(params.TenantID) {
		return fmt.Errorf("invalid TenantID format: must be a valid UUID")
	}

	// Validate ClientID format (UUID)
	if !isValidUUID(params.ClientID) {
		return fmt.Errorf("invalid ClientID format: must be a valid UUID")
	}

	// Validate URLs
	if err := validateURL(params.RedirectURL); err != nil {
		return fmt.Errorf("invalid RedirectURL: %w", err)
	}

	if err := validateURL(params.LogoutURLRedirect); err != nil {
		return fmt.Errorf("invalid LogoutURLRedirect: %w", err)
	}

	if err := validateURL(params.LoginURLRedirect); err != nil {
		return fmt.Errorf("invalid LoginURLRedirect: %w", err)
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
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims map[string]any
	if err := idTokenObj.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}
	return claims, nil
}

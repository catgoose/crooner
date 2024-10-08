package crooner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/exp/rand"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// AuthConfig contains the configuration for Azure AD authentication
type AuthConfig struct {
	OAuth2Config      *oauth2.Config        // OAuth2 configuration
	Provider          *oidc.Provider        // OIDC Provider for Azure AD
	Verifier          *oidc.IDTokenVerifier // Verifier to verify ID tokens
	AuthRoutes        *AuthRoutes           // Routes for authentication
	TenantID          string                // Azure AD Tenant ID
	LogoutURLRedirect string                // URL to redirect after logout
	LoginURLRedirect  string                // URL to redirect after login
}

// AuthConfigParams contains the parameters needed to configure Azure AD authentication
type AuthConfigParams struct {
	ClientID          string      // Azure AD Client ID
	ClientSecret      string      // Azure AD Client Secret
	TenantID          string      // Azure AD Tenant ID
	RedirectURL       string      // URL to redirect after login
	LogoutURLRedirect string      // URL to redirect after logout
	LoginURLRedirect  string      // URL to redirect after login
	AuthRoutes        *AuthRoutes // Routes for authentication
	SessionSecret     string      // Session secret for crooner cookie store
	AdditionalScopes  []string    // Additional scopes to request during authentication
}

// AuthRoutes contains the routes for authentication
type AuthRoutes struct {
	Login      string   // Login route
	Logout     string   // Logout route
	Callback   string   // Callback route for receiving authorization code
	AuthExempt []string // Routes to be exempt from auth
}

// NewAuthConfig creates a new AuthConfig based on the provided parameters
func NewAuthConfig(e *echo.Echo, ctx context.Context, params *AuthConfigParams) error {
	// Validate parameters
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
	}

	if params.SessionSecret != "" {
		store := sessions.NewCookieStore([]byte(params.SessionSecret))
		e.Use(session.Middleware(store))
	}

	authHandlerConfig := &AuthHandlerConfig{
		AuthConfig: authConfig,
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
	return nil
}

// GenerateCodeVerifier generates a random PKCE code verifier
func GenerateCodeVerifier() (string, error) {
	verifier := make([]byte, 64)
	if _, err := rand.Read(verifier); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(verifier), nil
}

// GenerateCodeChallenge generates a SHA256 code challenge from the verifier
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
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
func (c *AuthConfig) VerifyIDToken(ctx context.Context, idToken string) (map[string]interface{}, error) {
	idTokenObj, err := c.Verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims map[string]interface{}
	if err := idTokenObj.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}
	return claims, nil
}

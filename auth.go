package crooner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/coreos/go-oidc"
	"golang.org/x/exp/rand"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// AuthConfig contains the configuration for Azure AD authentication
type AuthConfig struct {
	OAuth2Config      *oauth2.Config        // OAuth2 configuration including ClientID, ClientSecret, etc.
	Provider          *oidc.Provider        // OIDC Provider for Azure AD
	Verifier          *oidc.IDTokenVerifier // Verifier to verify ID tokens
	TenantID          string                // Azure AD Tenant ID
	LogoutURLRedirect string                // URL to redirect after logout
	LoginURLRedirect  string                // URL to redirect after login
	CodeVerifier      string                // PKCE code verifier used during authentication
}

// AuthConfigParams contains the parameters needed to configure Azure AD authentication
type AuthConfigParams struct {
	ClientID          string   // Azure AD Client ID
	ClientSecret      string   // Azure AD Client Secret
	TenantID          string   // Azure AD Tenant ID
	RedirectURL       string   // URL to redirect after login
	LogoutURLRedirect string   // URL to redirect after logout
	LoginURLRedirect  string   // URL to redirect after login
	Scopes            []string // Scopes to request during authentication. profile and email are default
}

// NewAuthConfig creates a new AuthConfig based on the provided parameters
// It initializes the OAuth2 configuration and OIDC provider for Azure AD
func NewAuthConfig(ctx context.Context, params *AuthConfigParams) (*AuthConfig, error) {
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", params.TenantID))
	if err != nil {
		return nil, err
	}

	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	scopes = append(scopes, params.Scopes...)

	config := &AuthConfig{
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
	}

	return config, nil
}

// GenerateCodeVerifier generates a random PKCE code verifier
// This verifier is used in the OAuth2 flow to increase security
func (c *AuthConfig) GenerateCodeVerifier() (string, error) {
	verifier := make([]byte, 64)
	if _, err := rand.Read(verifier); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(verifier), nil
}

// GenerateCodeChallenge generates a SHA256 code challenge from the provided verifier
// This code challenge is used in the PKCE flow during authentication
func (c *AuthConfig) GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GetLoginURL constructs and returns the Azure AD login URL
// It uses the provided state and PKCE code challenge
func (c *AuthConfig) GetLoginURL(state, codeChallenge string) string {
	return c.OAuth2Config.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// ExchangeToken exchanges the authorization code for an access token
// This method uses the PKCE code verifier to complete the OAuth2 flow
func (c *AuthConfig) ExchangeToken(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return c.OAuth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
}

// VerifyIDToken verifies the provided ID token using the OIDC provider
// It extracts and returns the claims from the ID token
func (c *AuthConfig) VerifyIDToken(ctx context.Context, idToken string) (map[string]interface{}, error) {
	idTokenObj, err := c.Verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := idTokenObj.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

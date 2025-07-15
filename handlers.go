package crooner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"slices"

	"github.com/labstack/echo/v4"
)

// AuthHandlerConfig defines the configuration for handlers
type AuthHandlerConfig struct {
	AuthConfig         *AuthConfig
	SessionValueClaims []map[string]string
	SessionMgr         SessionManager // Use interface for all session operations
}

// authMiddleware generates a middleware to enforce authentication based on session data
func (a *AuthHandlerConfig) authMiddleware(routes *AuthRoutes) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if a.isAuthExemptRoute(c, routes) {
				return next(c)
			}

			// Retrieve and validate session
			if user, err := a.SessionMgr.Get(c, "user"); err != nil || user == nil {
				return c.Redirect(http.StatusFound, routes.Login)
			}

			return next(c)
		}
	}
}

// SetupAuth initializes the authentication middleware and routes
func (a *AuthHandlerConfig) SetupAuth(e *echo.Echo) {
	e.Use(a.securityHeadersMiddleware())
	e.Use(a.secureSessionMiddleware())
	e.Use(a.authMiddleware(a.AuthConfig.AuthRoutes))

	routes := a.AuthConfig.AuthRoutes
	e.GET(routes.Login, a.loginHandler())
	e.GET(routes.Callback, a.callbackHandler())
	e.GET(routes.Logout, a.logoutHandler())
}

// loginHandler creates a handler function for the login route
func (a *AuthHandlerConfig) loginHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		// Generate secure state parameter
		state, err := GenerateState()
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to generate state", err)
		}

		// Store state in session
		if err := a.SessionMgr.Set(c, "oauth_state", state); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}

		codeVerifier, err := GenerateCodeVerifier()
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to generate code verifier", err)
		}
		codeChallenge := GenerateCodeChallenge(codeVerifier)
		// Save code verifier in session
		if err := a.SessionMgr.Set(c, "code_verifier", codeVerifier); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}
		loginURL := a.AuthConfig.GetLoginURL(state, codeChallenge)
		return c.Redirect(http.StatusTemporaryRedirect, loginURL)
	}
}

// callbackHandler creates a handler function for the callback route
func (a *AuthHandlerConfig) callbackHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := a.SessionMgr.Get(c, "oauth_state")
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to get session", err)
		}

		// Validate state parameter
		expectedState, ok := sess.(string)
		if !ok {
			return a.handleError(c, http.StatusBadRequest, "State not found in session", nil)
		}

		receivedState := c.QueryParam("state")
		if receivedState != expectedState {
			return a.handleError(c, http.StatusBadRequest, "Invalid state parameter", nil)
		}

		// Clear state from session
		if err := a.SessionMgr.Delete(c, "oauth_state"); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear state from session", err)
		}

		sess, err = a.SessionMgr.Get(c, "code_verifier")
		if err != nil {
			return a.handleError(c, http.StatusBadRequest, "Code verifier not found", nil)
		}
		codeVerifier, ok := sess.(string)
		if !ok {
			return a.handleError(c, http.StatusBadRequest, "Code verifier not found", nil)
		}
		code := c.QueryParam("code")
		if code == "" {
			return a.handleError(c, http.StatusBadRequest, "Authorization code not provided", nil)
		}
		token, err := a.AuthConfig.ExchangeToken(c.Request().Context(), code, codeVerifier)
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to exchange token", err)
		}
		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			return a.handleError(c, http.StatusInternalServerError, "ID token not found in token response", nil)
		}
		claims, err := a.AuthConfig.VerifyIDToken(c.Request().Context(), idToken)
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to verify ID token", err)
		}
		if err := a.SessionMgr.Set(c, "user", claims["email"]); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}
		if a.SessionValueClaims != nil {
			for _, valueMap := range a.SessionValueClaims {
				for key, claim := range valueMap {
					if val, ok := claims[claim]; ok {
						if slice, isSlice := val.([]any); isSlice {
							var sliceStrings []string
							for _, role := range slice {
								if strRole, isString := role.(string); isString {
									sliceStrings = append(sliceStrings, strRole)
								}
							}
							val = sliceStrings
						}
						if err := a.SessionMgr.Set(c, key, val); err != nil {
							return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
						}
					}
				}
			}
		}
		return c.Redirect(http.StatusFound, a.AuthConfig.LoginURLRedirect)
	}
}

// logoutHandler creates a handler function for the logout route
func (a *AuthHandlerConfig) logoutHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := a.SessionMgr.Clear(c); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear session", err)
		}

		// Validate redirect URL
		if err := a.validateRedirectURL(a.AuthConfig.LogoutURLRedirect); err != nil {
			return a.handleError(c, http.StatusBadRequest, "Invalid redirect URL", err)
		}

		logoutURL := fmt.Sprintf(
			"https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
			a.AuthConfig.TenantID,
			url.QueryEscape(a.AuthConfig.LogoutURLRedirect),
		)
		return c.Redirect(http.StatusFound, logoutURL)
	}
}

// isAuthExemptRoute checks if the current route is exempt from authentication
func (a *AuthHandlerConfig) isAuthExemptRoute(c echo.Context, routes *AuthRoutes) bool {
	if strings.HasPrefix(c.Path(), routes.Login) ||
		strings.HasPrefix(c.Path(), routes.Callback) ||
		strings.HasPrefix(c.Path(), routes.Logout) {
		return true
	}
	for _, route := range routes.AuthExempt {
		if strings.HasPrefix(c.Path(), route) {
			return true
		}
	}
	return false
}

// Session helper methods
func (a *AuthHandlerConfig) handleError(c echo.Context, status int, message string, err error) error {
	// Always log detailed errors internally
	if err != nil {
		c.Logger().Errorf("Auth error: %s - %v", message, err)
	}

	// Return user-friendly message
	userMessage := ErrGenericAuth
	if a.AuthConfig.ErrorConfig != nil && a.AuthConfig.ErrorConfig.ShowDetails {
		if err != nil {
			userMessage = fmt.Sprintf("%s: %s", message, err.Error())
		} else {
			userMessage = message
		}
	}

	return c.String(status, userMessage)
}

// validateRedirectURL validates redirect URLs with security checks
func (a *AuthHandlerConfig) validateRedirectURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Require HTTPS in production
	if a.AuthConfig.URLValidation != nil && a.AuthConfig.URLValidation.RequireHTTPS {
		if parsedURL.Scheme != "https" {
			return fmt.Errorf("HTTPS required for redirect URLs")
		}
	}

	// Validate scheme
	if a.AuthConfig.URLValidation != nil && len(a.AuthConfig.URLValidation.AllowedSchemes) > 0 {
		if !slices.Contains(a.AuthConfig.URLValidation.AllowedSchemes, parsedURL.Scheme) {
			return fmt.Errorf("scheme %s not allowed", parsedURL.Scheme)
		}
	}

	// Validate domain
	if a.AuthConfig.URLValidation != nil && len(a.AuthConfig.URLValidation.AllowedDomains) > 0 {
		domainAllowed := false
		for _, domain := range a.AuthConfig.URLValidation.AllowedDomains {
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

// secureSessionMiddleware configures secure session options
func (a *AuthHandlerConfig) secureSessionMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Session options should be set in the app, not here
			return next(c)
		}
	}
}

// securityHeadersMiddleware adds security headers to responses
func (a *AuthHandlerConfig) securityHeadersMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("X-Content-Type-Options", "nosniff")
			c.Response().Header().Set("X-Frame-Options", "DENY")
			c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
			c.Response().Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			csp := "default-src 'self'"
			if a.AuthConfig.SecurityHeaders != nil && a.AuthConfig.SecurityHeaders.ContentSecurityPolicy != "" {
				csp = a.AuthConfig.SecurityHeaders.ContentSecurityPolicy
			}
			c.Response().Header().Set("Content-Security-Policy", csp)
			return next(c)
		}
	}
}

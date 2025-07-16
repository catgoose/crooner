package crooner

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"
)

// AuthHandlerConfig defines the configuration for handlers
type AuthHandlerConfig struct {
	AuthConfig         *AuthConfig
	SessionValueClaims []map[string]string
	SessionMgr         SessionManager // Use interface for all session operations
}

// SessionError represents an error related to session operations.
type SessionError struct {
	Key    string // The session key involved
	Reason string // A human-readable reason for the error
}

func (e *SessionError) Error() string {
	return fmt.Sprintf("session error for key %q: %s", e.Key, e.Reason)
}

// getSessionString retrieves a string from the session or returns a SessionError.
func (a *AuthHandlerConfig) getSessionString(c echo.Context, key string) (string, error) {
	val, err := a.SessionMgr.Get(c, key)
	if err != nil {
		return "", &SessionError{Key: key, Reason: "not found"}
	}
	str, ok := val.(string)
	if !ok {
		return "", &SessionError{Key: key, Reason: "not a string"}
	}
	return str, nil
}

// authMiddleware generates a middleware to enforce authentication based on session data
func (a *AuthHandlerConfig) authMiddleware(routes *AuthRoutes) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if a.isAuthExemptRoute(c, routes) {
				return next(c)
			}

			// Retrieve and validate session
			if _, err := a.getSessionString(c, "user"); err != nil {
				return c.Redirect(http.StatusFound, routes.Login)
			}

			return next(c)
		}
	}
}

// SetupAuth initializes the authentication middleware and routes
func (a *AuthHandlerConfig) SetupAuth(e *echo.Echo) {
	e.Use(a.securityHeadersMiddleware())
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
		expectedState, err := a.getSessionString(c, "oauth_state")
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to get session", err)
		}

		// Validate state parameter
		receivedState := c.QueryParam("state")
		if receivedState != expectedState {
			return a.handleError(c, http.StatusBadRequest, "Invalid state parameter", nil)
		}

		// Clear state from session
		if err := a.SessionMgr.Delete(c, "oauth_state"); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear state from session", err)
		}

		codeVerifier, err := a.getSessionString(c, "code_verifier")
		if err != nil {
			return a.handleError(c, http.StatusBadRequest, "Code verifier not found", err)
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
		// Use ClearInvalidate for full session cleanup
		if err := a.SessionMgr.ClearInvalidate(c); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear/invalidate session", err)
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

// ErrorResponse represents a standard JSON error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

func (a *AuthHandlerConfig) handleError(c echo.Context, status int, message string, err error) error {
	// Always log detailed errors internally
	if err != nil {
		c.Logger().Errorf("Auth error: %s - %v", message, err)
	}

	resp := ErrorResponse{
		Error: message,
	}
	if a.AuthConfig.ErrorConfig != nil && a.AuthConfig.ErrorConfig.ShowDetails && err != nil {
		resp.Details = err.Error()
	}

	return c.JSON(status, resp)
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

// securityHeadersMiddleware adds security headers to responses
func (a *AuthHandlerConfig) securityHeadersMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			h := a.AuthConfig.SecurityHeaders
			if h == nil {
				h = &SecurityHeadersConfig{}
			}

			headers := []struct {
				key   string
				value string
				def   string
			}{
				{"Content-Security-Policy", h.ContentSecurityPolicy, "default-src 'self'"},
				{"X-Frame-Options", h.XFrameOptions, "DENY"},
				{"X-Content-Type-Options", h.XContentTypeOptions, "nosniff"},
				{"Referrer-Policy", h.ReferrerPolicy, "strict-origin-when-cross-origin"},
				{"X-XSS-Protection", h.XXSSProtection, "1; mode=block"},
			}

			for _, hdr := range headers {
				val := hdr.def
				if hdr.value != "" {
					val = hdr.value
				}
				c.Response().Header().Set(hdr.key, val)
			}

			// Set Strict-Transport-Security only if config is non-empty and request is HTTPS
			if h.StrictTransportSecurity != "" && c.Scheme() == "https" {
				c.Response().Header().Set("Strict-Transport-Security", h.StrictTransportSecurity)
			}

			return next(c)
		}
	}
}

package crooner

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

// AuthHandlerConfig defines the configuration for handlers
type AuthHandlerConfig struct {
	AuthConfig *AuthConfig
}

// NewAuthHandlerConfig creates a new configuration for the auth handlers
func NewAuthHandlerConfig(authConfig *AuthConfig) *AuthHandlerConfig {
	return &AuthHandlerConfig{
		AuthConfig: authConfig,
	}
}

// LoginHandler creates a handler function for the login route
func (a *AuthHandlerConfig) LoginHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		codeVerifier, err := a.AuthConfig.GenerateCodeVerifier()
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to generate code verifier")
		}

		codeChallenge := a.AuthConfig.GenerateCodeChallenge(codeVerifier)

		sess, err := session.Get("session-name", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to get session")
		}

		sess.Values["code_verifier"] = codeVerifier
		err = sess.Save(c.Request(), c.Response())
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to save session")
		}

		// Return the login URL to the caller
		loginURL := a.AuthConfig.GetLoginURL("state", codeChallenge)
		return c.Redirect(http.StatusTemporaryRedirect, loginURL)
	}
}

// CallbackHandler creates a handler function for the callback route
func (a *AuthHandlerConfig) CallbackHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session-name", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to get session")
		}

		codeVerifier, ok := sess.Values["code_verifier"].(string)
		if !ok {
			return c.String(http.StatusBadRequest, "Code verifier not found")
		}

		code := c.QueryParam("code")
		if code == "" {
			return c.String(http.StatusBadRequest, "Authorization code not provided")
		}

		token, err := a.AuthConfig.ExchangeToken(c.Request().Context(), code, codeVerifier)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to exchange token")
		}

		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			return c.String(http.StatusInternalServerError, "ID token not found in token response")
		}

		claims, err := a.AuthConfig.VerifyIDToken(c.Request().Context(), idToken)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to verify ID token")
		}

		sess.Values["user"] = claims["email"]
		err = sess.Save(c.Request(), c.Response())
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to save session")
		}

		// Redirect to the provided URL
		return c.Redirect(http.StatusFound, a.AuthConfig.LoginURLRedirect)
	}
}

// LogoutHandler creates a handler function for the logout route
func (a *AuthHandlerConfig) LogoutHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		// Clear the local session
		sess, err := session.Get("session-name", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to get session")
		}

		delete(sess.Values, "user")
		err = sess.Save(c.Request(), c.Response())
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to save session")
		}

		// Ensure the redirect URL is valid
		if !isAbsoluteURL(a.AuthConfig.LogoutURLRedirect) {
			return c.String(http.StatusBadRequest, "Invalid redirect URL")
		}

		// Azure AD logout URL
		logoutURL := fmt.Sprintf(
			"https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
			a.AuthConfig.TenantID,
			url.QueryEscape(a.AuthConfig.LogoutURLRedirect), // Escape the redirect URL
		)

		// Redirect the user to the Azure AD logout URL
		return c.Redirect(http.StatusFound, logoutURL)
	}
}

// isAbsoluteURL checks if the given URL is an absolute URL
func isAbsoluteURL(rawURL string) bool {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Check if the URL has a valid scheme and host
	return parsedURL.Scheme != "" && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https") && parsedURL.Host != ""
}

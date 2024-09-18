package crooner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

// AuthHandlerConfig defines the configuration for handlers
type AuthHandlerConfig struct {
	AuthConfig *AuthConfig
}

// authMiddleware generates a middleware to enforce authentication based on session data
func (a *AuthHandlerConfig) authMiddleware(routes AuthRoutes) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if a.isAuthExemptRoute(c, routes) {
				return next(c)
			}

			// Retrieve and validate session
			if sess, err := a.getSession(c); err != nil || sess.Values["user"] == nil {
				return c.Redirect(http.StatusFound, routes.Login)
			}

			return next(c)
		}
	}
}

// SetupAuth initializes the authentication middleware and routes
func (a *AuthHandlerConfig) SetupAuth(e *echo.Echo) {
	e.Use(a.authMiddleware(*a.AuthConfig.AuthRoutes))

	routes := a.AuthConfig.AuthRoutes
	e.GET(routes.Login, a.loginHandler())
	e.GET(routes.Callback, a.callbackHandler())
	e.GET(routes.Logout, a.logoutHandler())
}

// loginHandler creates a handler function for the login route
func (a *AuthHandlerConfig) loginHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		codeVerifier, err := GenerateCodeVerifier()
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to generate code verifier", err)
		}

		codeChallenge := GenerateCodeChallenge(codeVerifier)

		// Save code verifier in session
		if err := a.saveSessionValue(c, "code_verifier", codeVerifier); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}

		loginURL := a.AuthConfig.GetLoginURL("state", codeChallenge)
		return c.Redirect(http.StatusTemporaryRedirect, loginURL)
	}
}

// callbackHandler creates a handler function for the callback route
func (a *AuthHandlerConfig) callbackHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := a.getSession(c)
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to get session", err)
		}

		codeVerifier, ok := sess.Values["code_verifier"].(string)
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

		if err := a.saveSessionValue(c, "user", claims["email"]); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}

		return c.Redirect(http.StatusFound, a.AuthConfig.LoginURLRedirect)
	}
}

// logoutHandler creates a handler function for the logout route
func (a *AuthHandlerConfig) logoutHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := a.clearSession(c); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear session", err)
		}

		if !a.isAbsoluteURL(a.AuthConfig.LogoutURLRedirect) {
			return a.handleError(c, http.StatusBadRequest, "Invalid redirect URL", nil)
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
func (a *AuthHandlerConfig) isAuthExemptRoute(c echo.Context, routes AuthRoutes) bool {
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
func (a *AuthHandlerConfig) getSession(c echo.Context) (*sessions.Session, error) {
	return session.Get("crooner-auth", c)
}

func (a *AuthHandlerConfig) saveSessionValue(c echo.Context, key string, value interface{}) error {
	sess, err := a.getSession(c)
	if err != nil {
		return err
	}
	sess.Values[key] = value
	return sess.Save(c.Request(), c.Response())
}

func (a *AuthHandlerConfig) clearSession(c echo.Context) error {
	sess, err := a.getSession(c)
	if err != nil {
		return err
	}
	delete(sess.Values, "user")
	return sess.Save(c.Request(), c.Response())
}

func (a *AuthHandlerConfig) handleError(c echo.Context, status int, message string, err error) error {
	if err != nil {
		fmt.Println("Error:", err)
	}
	return c.String(status, message)
}

func (a *AuthHandlerConfig) isAbsoluteURL(rawURL string) bool {
	parsedURL, err := url.Parse(rawURL)
	return err == nil && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https") && parsedURL.Host != ""
}

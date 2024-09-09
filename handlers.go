package crooner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
)

// AuthHandlerConfig defines the configuration for handlers
type AuthHandlerConfig struct {
	AuthConfig *AuthConfig
	Store      *sessions.CookieStore
}

// NewAuthHandlerConfig creates a new configuration for the auth handlers
func NewAuthHandlerConfig(authConfig *AuthConfig, store *sessions.CookieStore) *AuthHandlerConfig {
	return &AuthHandlerConfig{
		AuthConfig: authConfig,
		Store:      store,
	}
}

// LoginHandler creates a handler function for the login route
// The caller can provide a redirectURL to decide where the user should be redirected after login.
func (a *AuthHandlerConfig) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		codeVerifier, err := a.AuthConfig.GenerateCodeVerifier()
		if err != nil {
			http.Error(w, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}

		codeChallenge := a.AuthConfig.GenerateCodeChallenge(codeVerifier)
		session, _ := a.Store.Get(r, "session-name")
		session.Values["code_verifier"] = codeVerifier
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}

		// Return the login URL to the caller
		loginURL := a.AuthConfig.GetLoginURL("state", codeChallenge)
		w.Header().Set("Location", loginURL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
}

// CallbackHandler creates a handler function for the callback route
// The caller can provide a redirectURL to decide where the user should be redirected after successful login.
func (a *AuthHandlerConfig) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := a.Store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}

		codeVerifier, ok := session.Values["code_verifier"].(string)
		if !ok {
			http.Error(w, "Code verifier not found", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not provided", http.StatusBadRequest)
			return
		}

		token, err := a.AuthConfig.ExchangeToken(context.Background(), code, codeVerifier)
		if err != nil {
			http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
			return
		}

		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "ID token not found in token response", http.StatusInternalServerError)
			return
		}

		claims, err := a.AuthConfig.VerifyIDToken(context.Background(), idToken)
		if err != nil {
			http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
			return
		}

		session.Values["user"] = claims["email"]
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}

		// Redirect to the provided URL
		w.Header().Set("Location", a.AuthConfig.LoginURLRedirect)
		w.WriteHeader(http.StatusFound)
	}
}

// LogoutHandler creates a handler function for the logout route
func (a *AuthHandlerConfig) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear the local session
		session, _ := a.Store.Get(r, "session-name")
		session.Values["user"] = ""
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}

		// Ensure the redirect URL is valid
		if !isAbsoluteURL(a.AuthConfig.LogoutURLRedirect) {
			http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
			return
		}

		// Azure AD logout URL
		logoutURL := fmt.Sprintf(
			"https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
			a.AuthConfig.TenantID,
			url.QueryEscape(a.AuthConfig.LogoutURLRedirect), // Escape the redirect URL
		)

		// Redirect the user to the Azure AD logout URL
		http.Redirect(w, r, logoutURL, http.StatusFound)
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

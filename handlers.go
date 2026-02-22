package crooner

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

// AuthHandlerConfig is internal: it ties AuthConfig to a SessionManager and optional claim mapping; created by NewAuthConfig.
type AuthHandlerConfig struct {
	SessionMgr SessionManager
	*AuthConfig
	SessionValueClaims []map[string]string
}

// userClaimValue returns the first non-empty string from claims for the given claim names (primary then fallbacks).
func userClaimValue(claims map[string]any, primary string) string {
	try := []string{primary}
	if primary != "email" {
		try = append(try, "email")
	}
	if primary != "preferred_username" {
		try = append(try, "preferred_username")
	}
	if primary != "upn" {
		try = append(try, "upn")
	}
	for _, key := range try {
		if v, ok := claims[key]; ok && v != nil {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// RequireAuth returns Echo middleware that requires a session user. Exempt paths (login, callback, logout, AuthExempt) skip the check. Unauthenticated requests are redirected to the login route with a redirect parameter.
func RequireAuth(sm SessionManager, routes *AuthRoutes) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if IsAuthExemptPath(c.Path(), routes) {
				return next(c)
			}
			if _, err := GetString(sm, c, SessionKeyUser); err != nil {
				return c.Redirect(http.StatusFound, loginRedirectURL(routes, c.Request().RequestURI))
			}
			return next(c)
		}
	}
}

// SetupAuth initializes the authentication middleware and routes
func (a *AuthHandlerConfig) SetupAuth(e *echo.Echo) {
	e.Use(SecurityHeadersMiddleware(a.SecurityHeaders))
	e.Use(RequireAuth(a.SessionMgr, a.AuthRoutes))

	routes := a.AuthRoutes
	e.GET(routes.Login, a.loginHandler())
	e.GET(routes.Callback, a.callbackHandler())
	e.POST(routes.Logout, a.logoutHandler())
}

func safeRedirectTarget(a *AuthHandlerConfig) string {
	if a.LoginURLRedirect != "" {
		return a.LoginURLRedirect
	}
	return "/"
}

// loginHandler creates a handler function for the login route
func (a *AuthHandlerConfig) loginHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		csrfState, err := GenerateState()
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to generate state", err)
		}

		originalPath := c.QueryParam("redirect")
		if originalPath == "" {
			originalPath = c.Request().RequestURI
		}
		baseURL := c.Scheme() + "://" + c.Request().Host
		safePath, err := ValidatePostLoginRedirect(originalPath, baseURL, a.URLValidation)
		if err != nil {
			return c.Redirect(http.StatusFound, safeRedirectTarget(a))
		}
		state := EncodeStatePayload(csrfState, safePath)

		if err := a.SessionMgr.Set(c, SessionKeyOAuthState, state); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}

		codeVerifier, err := GenerateCodeVerifier()
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to generate code verifier", err)
		}
		codeChallenge := GenerateCodeChallenge(codeVerifier)
		if err := a.SessionMgr.Set(c, SessionKeyCodeVerifier, codeVerifier); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}
		nonce, err := GenerateState()
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to generate nonce", err)
		}
		if err := a.SessionMgr.Set(c, SessionKeyOAuthNonce, nonce); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save nonce", err)
		}
		loginURL := a.GetLoginURL(state, codeChallenge, nonce)
		return c.Redirect(http.StatusTemporaryRedirect, loginURL)
	}
}

// callbackHandler creates a handler function for the callback route
func (a *AuthHandlerConfig) callbackHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		expectedState, err := GetString(a.SessionMgr, c, SessionKeyOAuthState)
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to get session", err)
		}

		receivedState := c.QueryParam("state")
		if subtle.ConstantTimeCompare([]byte(receivedState), []byte(expectedState)) != 1 {
			_ = a.SessionMgr.Delete(c, SessionKeyOAuthState)
			_ = a.SessionMgr.Delete(c, SessionKeyCodeVerifier)
			return c.Redirect(http.StatusFound, loginRedirectURL(a.AuthRoutes, c.Request().RequestURI))
		}

		originalPath, err := DecodeStatePayload(expectedState)
		if err != nil {
			_ = a.SessionMgr.Delete(c, SessionKeyOAuthState)
			_ = a.SessionMgr.Delete(c, SessionKeyCodeVerifier)
			if a.LoginURLRedirect != "" {
				return c.Redirect(http.StatusFound, a.LoginURLRedirect)
			}
			msg := "Invalid state data"
			if errors.Is(err, ErrInvalidStateFormat) {
				msg = "Invalid state format"
			}
			return a.handleError(c, http.StatusBadRequest, msg, err)
		}

		if err := a.SessionMgr.Delete(c, SessionKeyOAuthState); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear state from session", err)
		}

		codeVerifier, err := GetString(a.SessionMgr, c, SessionKeyCodeVerifier)
		if err != nil {
			_ = a.SessionMgr.Delete(c, SessionKeyCodeVerifier)
			return a.handleError(c, http.StatusBadRequest, "Code verifier not found", err)
		}
		code := c.QueryParam("code")
		if code == "" {
			_ = a.SessionMgr.Delete(c, SessionKeyCodeVerifier)
			return a.handleError(c, http.StatusBadRequest, "Authorization code not provided", ErrAuthorizationCodeNotProvided)
		}
		token, err := a.ExchangeToken(c.Request().Context(), code, codeVerifier)
		if err != nil {
			_ = a.SessionMgr.Delete(c, SessionKeyCodeVerifier)
			return a.handleError(c, http.StatusInternalServerError, "Failed to exchange token", err)
		}
		if err := a.SessionMgr.Delete(c, SessionKeyCodeVerifier); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear code verifier", err)
		}
		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			return a.handleError(c, http.StatusInternalServerError, "ID token not found in token response", nil)
		}
		claims, err := a.VerifyIDToken(c.Request().Context(), idToken)
		if err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to verify ID token", err)
		}
		expectedNonce, err := GetString(a.SessionMgr, c, SessionKeyOAuthNonce)
		if err != nil {
			return a.handleError(c, http.StatusBadRequest, "Nonce not found", err)
		}
		if err := a.SessionMgr.Delete(c, SessionKeyOAuthNonce); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear nonce", err)
		}
		claimNonce, _ := claims["nonce"].(string)
		if len(claimNonce) != len(expectedNonce) || subtle.ConstantTimeCompare([]byte(claimNonce), []byte(expectedNonce)) != 1 {
			return a.handleError(c, http.StatusBadRequest, "Nonce mismatch", ErrNonceMismatch)
		}
		userVal := userClaimValue(claims, a.UserClaim)
		if userVal == "" {
			return a.handleError(c, http.StatusInternalServerError, "No user claim found in token", nil)
		}
		if renewer, ok := a.SessionMgr.(SessionTokenRenewer); ok {
			if err := renewer.RenewToken(c); err != nil {
				return a.handleError(c, http.StatusInternalServerError, "Failed to renew session token", err)
			}
		}
		if err := a.SessionMgr.Set(c, SessionKeyUser, userVal); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}
		if err := SaveSessionValueClaims(a.SessionMgr, c, claims, a.SessionValueClaims); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to save session", err)
		}
		baseURL := c.Scheme() + "://" + c.Request().Host
		safePath, err := ValidatePostLoginRedirect(originalPath, baseURL, a.URLValidation)
		if err != nil {
			return c.Redirect(http.StatusFound, safeRedirectTarget(a))
		}
		return c.Redirect(http.StatusFound, safePath)
	}
}

// logoutHandler creates a handler function for the logout route
func (a *AuthHandlerConfig) logoutHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := a.SessionMgr.ClearInvalidate(c); err != nil {
			return a.handleError(c, http.StatusInternalServerError, "Failed to clear/invalidate session", err)
		}

		if err := ValidateRedirectURL(a.LogoutURLRedirect, a.URLValidation); err != nil {
			return a.handleError(c, http.StatusBadRequest, "Invalid redirect URL", err)
		}

		if a.EndSessionEndpoint != "" {
			sep := "?"
			if strings.Contains(a.EndSessionEndpoint, "?") {
				sep = "&"
			}
			logoutURL := a.EndSessionEndpoint + sep + "post_logout_redirect_uri=" + url.QueryEscape(a.LogoutURLRedirect)
			return c.Redirect(http.StatusFound, logoutURL)
		}
		if a.TenantID != "" {
			logoutURL := fmt.Sprintf(
				"https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
				a.TenantID,
				url.QueryEscape(a.LogoutURLRedirect),
			)
			return c.Redirect(http.StatusFound, logoutURL)
		}
		return c.Redirect(http.StatusFound, a.LogoutURLRedirect)
	}
}

const problemTypeBase = "https://github.com/catgoose/crooner/blob/main/docs/errors.md#"

const (
	problemTypeConfig         = problemTypeBase + "config"
	problemTypeAuth           = problemTypeBase + "auth"
	problemTypeChallenge      = problemTypeBase + "challenge"
	problemTypeSession        = problemTypeBase + "session"
	problemTypeInvalidState   = problemTypeBase + "invalid_state"
	problemTypeInvalidRequest = problemTypeBase + "invalid_request"
)

var problemTypeTitle = map[string]string{
	problemTypeConfig:         "Configuration error",
	problemTypeAuth:           "Authentication error",
	problemTypeChallenge:      "Challenge generation failed",
	problemTypeSession:        "Session error",
	problemTypeInvalidState:   "Invalid state",
	problemTypeInvalidRequest: "Invalid request",
}

var (
	ErrAuthorizationCodeNotProvided = errors.New("authorization code not provided")
	ErrNonceMismatch                = errors.New("nonce mismatch")
)

// ProblemDetails represents RFC 7807 / RFC 9457 problem details for HTTP API errors.
// Auth handlers return this with Content-Type application/problem+json.
type ProblemDetails struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	Key      string `json:"key,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Op       string `json:"op,omitempty"`
	Field    string `json:"field,omitempty"`
	Status   int    `json:"status"`
}

func problemTypeForErr(err error) string {
	if err == nil {
		return "about:blank"
	}
	var sessionErr *SessionError
	if errors.As(err, &sessionErr) {
		return problemTypeSession
	}
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return problemTypeAuth
	}
	var challengeErr *ChallengeError
	if errors.As(err, &challengeErr) {
		return problemTypeChallenge
	}
	var configErr *ConfigError
	if errors.As(err, &configErr) {
		return problemTypeConfig
	}
	if errors.Is(err, ErrInvalidStateFormat) || errors.Is(err, ErrInvalidStateData) {
		return problemTypeInvalidState
	}
	if errors.Is(err, ErrAuthorizationCodeNotProvided) || errors.Is(err, ErrNonceMismatch) {
		return problemTypeInvalidRequest
	}
	return "about:blank"
}

func (a *AuthHandlerConfig) handleError(c echo.Context, status int, message string, err error) error {
	if err != nil {
		c.Logger().Errorf("Auth error: %s - %v", message, err)
	}

	ptype := problemTypeForErr(err)
	title := problemTypeTitle[ptype]
	if title == "" {
		title = message
	}
	problem := ProblemDetails{
		Type:   ptype,
		Title:  title,
		Detail: message,
		Status: status,
	}
	if a.ErrorConfig != nil && a.ErrorConfig.ShowDetails && err != nil {
		problem.Detail = err.Error()
	}
	if req := c.Request(); req != nil && req.URL != nil {
		problem.Instance = c.Scheme() + "://" + req.Host + req.URL.RequestURI()
	}
	var sessionErr *SessionError
	if errors.As(err, &sessionErr) {
		problem.Key = sessionErr.Key
		problem.Reason = sessionErr.Reason
	}
	var authErr *AuthError
	if errors.As(err, &authErr) {
		problem.Op = authErr.Op
		problem.Reason = authErr.Reason
	}
	var configErr *ConfigError
	if errors.As(err, &configErr) {
		problem.Field = configErr.Field
		problem.Reason = configErr.Reason
	}

	c.Response().Header().Set("Content-Type", "application/problem+json")
	return c.JSON(status, problem)
}

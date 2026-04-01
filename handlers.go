package crooner

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// AuthHandlerConfig is internal: it ties AuthConfig to a SessionManager and optional claim mapping; created by NewAuthConfig.
type AuthHandlerConfig struct {
	SessionMgr SessionManager
	*AuthConfig
	SessionValueClaims map[string]string
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

// RequireAuth returns standard middleware that requires a session user. Exempt paths (login, callback, logout, AuthExempt) skip the check. Unauthenticated requests are redirected to the login route with a redirect parameter.
func RequireAuth(sm SessionManager, routes *AuthRoutes) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsAuthExemptPath(r.URL.Path, routes) {
				next.ServeHTTP(w, r)
				return
			}
			if _, err := GetString(sm, r, SessionKeyUser); err != nil {
				http.Redirect(w, r, loginRedirectURL(routes, r.RequestURI), http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SetupAuth initializes the authentication middleware and routes on a ServeMux.
// Middleware must be applied by the caller wrapping the mux. Use Middleware() to get
// the middleware chain. This method registers the auth handler routes on the mux.
func (a *AuthHandlerConfig) SetupAuth(mux *http.ServeMux) {
	routes := a.AuthRoutes
	mux.HandleFunc("GET "+routes.Login, a.LoginHandler())
	mux.HandleFunc("GET "+routes.Callback, a.CallbackHandler())
	mux.HandleFunc("POST "+routes.Logout, a.LogoutHandler())
}

// Middleware returns the standard middleware chain for auth: security headers
// and require-auth. Apply this by wrapping your mux.
func (a *AuthHandlerConfig) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		h := next
		h = RequireAuth(a.SessionMgr, a.AuthRoutes)(h)
		h = SecurityHeadersMiddleware(a.SecurityHeaders)(h)
		return h
	}
}

func safeRedirectTarget(a *AuthHandlerConfig) string {
	if a.LoginURLRedirect != "" {
		return a.LoginURLRedirect
	}
	return "/"
}

// requestScheme returns "https" if the request appears to be over TLS, otherwise "http".
func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

// LoginHandler creates a handler function for the login route
func (a *AuthHandlerConfig) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrfState, err := GenerateState()
		if err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to generate state", err)
			return
		}

		originalPath := r.URL.Query().Get("redirect")
		if originalPath == "" {
			originalPath = r.RequestURI
		}
		baseURL := requestScheme(r) + "://" + r.Host
		safePath, err := ValidatePostLoginRedirect(originalPath, baseURL, a.URLValidation)
		if err != nil {
			http.Redirect(w, r, safeRedirectTarget(a), http.StatusFound)
			return
		}
		state := EncodeStatePayload(csrfState, safePath)

		if err := a.SessionMgr.Set(r, SessionKeyOAuthState, state); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to save session", err)
			return
		}

		codeVerifier, err := GenerateCodeVerifier()
		if err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to generate code verifier", err)
			return
		}
		codeChallenge := GenerateCodeChallenge(codeVerifier)
		if err := a.SessionMgr.Set(r, SessionKeyCodeVerifier, codeVerifier); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to save session", err)
			return
		}
		nonce, err := GenerateState()
		if err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to generate nonce", err)
			return
		}
		if err := a.SessionMgr.Set(r, SessionKeyOAuthNonce, nonce); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to save nonce", err)
			return
		}
		loginURL := a.GetLoginURL(state, codeChallenge, nonce)
		http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
	}
}

// CallbackHandler creates a handler function for the callback route
func (a *AuthHandlerConfig) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedState, err := GetString(a.SessionMgr, r, SessionKeyOAuthState)
		if err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to get session", err)
			return
		}

		receivedState := r.URL.Query().Get("state")
		if subtle.ConstantTimeCompare([]byte(receivedState), []byte(expectedState)) != 1 {
			_ = a.SessionMgr.Delete(r, SessionKeyOAuthState)
			_ = a.SessionMgr.Delete(r, SessionKeyCodeVerifier)
			http.Redirect(w, r, loginRedirectURL(a.AuthRoutes, r.RequestURI), http.StatusFound)
			return
		}

		originalPath, err := DecodeStatePayload(expectedState)
		if err != nil {
			_ = a.SessionMgr.Delete(r, SessionKeyOAuthState)
			_ = a.SessionMgr.Delete(r, SessionKeyCodeVerifier)
			if a.LoginURLRedirect != "" {
				http.Redirect(w, r, a.LoginURLRedirect, http.StatusFound)
				return
			}
			msg := "Invalid state data"
			if errors.Is(err, ErrInvalidStateFormat) {
				msg = "Invalid state format"
			}
			a.handleError(w, r, http.StatusBadRequest, msg, err)
			return
		}

		if err := a.SessionMgr.Delete(r, SessionKeyOAuthState); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to clear state from session", err)
			return
		}

		codeVerifier, err := GetString(a.SessionMgr, r, SessionKeyCodeVerifier)
		if err != nil {
			_ = a.SessionMgr.Delete(r, SessionKeyCodeVerifier)
			a.handleError(w, r, http.StatusBadRequest, "Code verifier not found", err)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			_ = a.SessionMgr.Delete(r, SessionKeyCodeVerifier)
			a.handleError(w, r, http.StatusBadRequest, "Authorization code not provided", ErrAuthorizationCodeNotProvided)
			return
		}
		token, err := a.ExchangeToken(r.Context(), code, codeVerifier)
		if err != nil {
			_ = a.SessionMgr.Delete(r, SessionKeyCodeVerifier)
			a.handleError(w, r, http.StatusInternalServerError, "Failed to exchange token", err)
			return
		}
		if err := a.SessionMgr.Delete(r, SessionKeyCodeVerifier); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to clear code verifier", err)
			return
		}
		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			a.handleError(w, r, http.StatusInternalServerError, "ID token not found in token response", nil)
			return
		}
		claims, err := a.VerifyIDToken(r.Context(), idToken)
		if err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to verify ID token", err)
			return
		}
		expectedNonce, err := GetString(a.SessionMgr, r, SessionKeyOAuthNonce)
		if err != nil {
			a.handleError(w, r, http.StatusBadRequest, "Nonce not found", err)
			return
		}
		if err := a.SessionMgr.Delete(r, SessionKeyOAuthNonce); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to clear nonce", err)
			return
		}
		claimNonce, _ := claims["nonce"].(string)
		if len(claimNonce) != len(expectedNonce) || subtle.ConstantTimeCompare([]byte(claimNonce), []byte(expectedNonce)) != 1 {
			a.handleError(w, r, http.StatusBadRequest, "Nonce mismatch", ErrNonceMismatch)
			return
		}
		userVal := userClaimValue(claims, a.UserClaim)
		if userVal == "" {
			a.handleError(w, r, http.StatusInternalServerError, "No user claim found in token", nil)
			return
		}
		if renewer, ok := a.SessionMgr.(SessionTokenRenewer); ok {
			if err := renewer.RenewToken(r); err != nil {
				a.handleError(w, r, http.StatusInternalServerError, "Failed to renew session token", err)
				return
			}
		}
		if err := a.SessionMgr.Set(r, SessionKeyUser, userVal); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to save session", err)
			return
		}
		if err := SaveSessionValueClaims(a.SessionMgr, r, claims, a.SessionValueClaims); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to save session", err)
			return
		}
		baseURL := requestScheme(r) + "://" + r.Host
		safePath, err := ValidatePostLoginRedirect(originalPath, baseURL, a.URLValidation)
		if err != nil {
			http.Redirect(w, r, safeRedirectTarget(a), http.StatusFound)
			return
		}
		http.Redirect(w, r, safePath, http.StatusFound)
	}
}

// LogoutHandler creates a handler function for the logout route
func (a *AuthHandlerConfig) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := a.SessionMgr.ClearInvalidate(r); err != nil {
			a.handleError(w, r, http.StatusInternalServerError, "Failed to clear/invalidate session", err)
			return
		}

		if err := ValidateRedirectURL(a.LogoutURLRedirect, a.URLValidation); err != nil {
			a.handleError(w, r, http.StatusBadRequest, "Invalid redirect URL", err)
			return
		}

		if a.EndSessionEndpoint != "" {
			sep := "?"
			if strings.Contains(a.EndSessionEndpoint, "?") {
				sep = "&"
			}
			logoutURL := a.EndSessionEndpoint + sep + "post_logout_redirect_uri=" + url.QueryEscape(a.LogoutURLRedirect)
			http.Redirect(w, r, logoutURL, http.StatusFound)
			return
		}
		http.Redirect(w, r, a.LogoutURLRedirect, http.StatusFound)
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

func (a *AuthHandlerConfig) handleError(w http.ResponseWriter, r *http.Request, status int, message string, err error) {
	if err != nil {
		log.Printf("Auth error: %s - %v", message, err)
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
	if r != nil && r.URL != nil {
		problem.Instance = requestScheme(r) + "://" + r.Host + r.URL.RequestURI()
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

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem)
}

package crooner_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	crooner "github.com/catgoose/crooner"
)

// ExampleNewSCSManager demonstrates creating a session manager with
// functional options and secure defaults.
func ExampleNewSCSManager() {
	sessionMgr, scsMgr, err := crooner.NewSCSManager(
		crooner.WithPersistentCookieName("my-strong-secret", "myapp"),
		crooner.WithLifetime(12*time.Hour),
		crooner.WithCookieDomain("example.com"),
		crooner.WithCookiePath("/"),
		crooner.WithCookieSecure(true),
		crooner.WithCookieHTTPOnly(true),
		crooner.WithCookieSameSite(http.SameSiteLaxMode),
	)
	if err != nil {
		panic(err)
	}

	_ = scsMgr // use scsMgr.LoadAndSave as middleware

	fmt.Println("cookie:", sessionMgr.GetCookieName())
	// Output:
	// cookie: crooner-cb313aaf1f73f65a
}

// ExampleNewSCSManagerWithConfig demonstrates creating a session manager
// from an explicit SessionConfig struct for advanced use cases.
func ExampleNewSCSManagerWithConfig() {
	cfg := crooner.DefaultSecureSessionConfig()
	cfg.CookieName = "crooner-custom"
	cfg.Lifetime = 7 * 24 * time.Hour
	cfg.CookieDomain = ".example.com"
	cfg.CookieSameSite = http.SameSiteStrictMode
	cfg.CookieSecure = true

	sessionMgr, _, err := crooner.NewSCSManagerWithConfig(cfg)
	if err != nil {
		panic(err)
	}

	fmt.Println("cookie:", sessionMgr.GetCookieName())
	// Output:
	// cookie: crooner-custom
}

// ExampleNewAuthConfig demonstrates configuring the full OIDC authentication
// flow using standard net/http. NewAuthConfig returns an AuthHandlerConfig;
// call SetupAuth(mux) to register login, callback, and logout routes, then
// use Middleware() for security-header and auth-required middleware.
//
// In a real application the issuer URL, client ID, secrets, and redirect
// URLs come from environment variables or a config file.
func ExampleNewAuthConfig() {
	mux := http.NewServeMux()

	sessionMgr, scsMgr, err := crooner.NewSCSManager(
		crooner.WithPersistentCookieName("secret", "myapp"),
		crooner.WithLifetime(12*time.Hour),
	)
	if err != nil {
		panic(err)
	}

	params := &crooner.AuthConfigParams{
		IssuerURL:         "https://accounts.example.com",
		ClientID:          "my-client-id",
		ClientSecret:      "my-client-secret",
		RedirectURL:       "https://app.example.com/callback",
		LogoutURLRedirect: "https://app.example.com/",
		LoginURLRedirect:  "https://app.example.com/",
		SessionMgr:        sessionMgr,
		AuthRoutes: &crooner.AuthRoutes{
			Login:    "/login",
			Logout:   "/logout",
			Callback: "/callback",
		},
	}

	ctx := context.Background()
	authHandler, err := crooner.NewAuthConfig(ctx, params)
	if err != nil {
		// NewAuthConfig contacts the OIDC issuer at startup; handle
		// discovery errors gracefully.
		fmt.Println("auth config error:", err)
	}

	// Register auth routes on the mux
	if authHandler != nil {
		authHandler.SetupAuth(mux)
	}

	// Wrap the mux with middleware (session loading + auth)
	var handler http.Handler = mux
	if authHandler != nil {
		handler = authHandler.Middleware()(handler)
	}
	handler = scsMgr.LoadAndSave(handler)
	_ = handler // use with http.ListenAndServe
}

// ExampleSecurityHeadersConfig demonstrates customizing the security
// headers applied to every response.
func ExampleSecurityHeadersConfig() {
	_ = &crooner.SecurityHeadersConfig{
		ContentSecurityPolicy:   "default-src 'self'; script-src 'self' cdn.example.com",
		XFrameOptions:           "DENY",
		XContentTypeOptions:     "nosniff",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		XXSSProtection:          "1; mode=block",
		StrictTransportSecurity: "max-age=63072000; includeSubDomains; preload",
	}

	fmt.Println("headers configured")
	// Output:
	// headers configured
}

// ExampleRequireAuth demonstrates adding the RequireAuth middleware to
// protect routes that need an authenticated session. Unauthenticated
// requests are redirected to the login route.
func ExampleRequireAuth() {
	sessionMgr, scsMgr, err := crooner.NewSCSManager(
		crooner.WithPersistentCookieName("secret", "myapp"),
		crooner.WithLifetime(12*time.Hour),
	)
	if err != nil {
		panic(err)
	}

	routes := &crooner.AuthRoutes{
		Login:    "/login",
		Logout:   "/logout",
		Callback: "/callback",
		AuthExempt: []string{
			"/health",
			"/public",
		},
	}

	mux := http.NewServeMux()

	// Protected route -- requires a session with a "user" key.
	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	// Exempt route -- accessible without authentication.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Wrap with middleware
	handler := crooner.RequireAuth(sessionMgr, routes)(mux)
	handler = scsMgr.LoadAndSave(handler)
	_ = handler

	fmt.Println("routes registered")
	// Output:
	// routes registered
}

// ExampleDefaultSecureSessionConfig demonstrates retrieving the default
// secure session configuration and customizing individual fields.
func ExampleDefaultSecureSessionConfig() {
	cfg := crooner.DefaultSecureSessionConfig()

	fmt.Println("secure:", cfg.CookieSecure)
	fmt.Println("httponly:", cfg.CookieHTTPOnly)
	fmt.Println("samesite:", cfg.CookieSameSite)
	fmt.Println("lifetime:", cfg.Lifetime)
	// Output:
	// secure: true
	// httponly: true
	// samesite: 2
	// lifetime: 24h0m0s
}

// ExamplePersistentCookieSuffix demonstrates generating a deterministic,
// non-guessable cookie-name suffix from a secret and application name.
func ExamplePersistentCookieSuffix() {
	suffix := crooner.PersistentCookieSuffix("my-strong-secret", "myapp")
	cookieName := "crooner-" + suffix

	fmt.Println(cookieName)
	// Output:
	// crooner-cb313aaf1f73f65a
}

// ExampleGenerateCodeVerifier demonstrates generating a PKCE code verifier
// and its corresponding code challenge.
func ExampleGenerateCodeVerifier() {
	verifier, err := crooner.GenerateCodeVerifier()
	if err != nil {
		panic(err)
	}
	challenge := crooner.GenerateCodeChallenge(verifier)

	fmt.Println("verifier length:", len(verifier))
	fmt.Println("challenge length:", len(challenge))
	// Output:
	// verifier length: 86
	// challenge length: 43
}

// ExampleEncodeStatePayload demonstrates encoding and decoding the OAuth
// state parameter that carries both a state token and the original path
// through the login flow.
func ExampleEncodeStatePayload() {
	state := crooner.EncodeStatePayload("random-csrf-token", "/dashboard?id=42")
	originalPath, err := crooner.DecodeStatePayload(state)
	if err != nil {
		panic(err)
	}

	fmt.Println("original path:", originalPath)
	// Output:
	// original path: /dashboard?id=42
}

// ExampleValidateRedirectURL demonstrates validating an absolute redirect
// URL with optional domain and scheme constraints.
func ExampleValidateRedirectURL() {
	uv := &crooner.URLValidationConfig{
		AllowedSchemes: []string{"https"},
		AllowedDomains: []string{"example.com"},
		RequireHTTPS:   true,
	}

	err := crooner.ValidateRedirectURL("https://example.com/callback", uv)
	fmt.Println("valid:", err == nil)

	err = crooner.ValidateRedirectURL("http://evil.com/callback", uv)
	fmt.Println("invalid:", err != nil)
	// Output:
	// valid: true
	// invalid: true
}

// ExampleValidatePostLoginRedirect demonstrates validating the relative
// path used as the post-login redirect target.
func ExampleValidatePostLoginRedirect() {
	safe, err := crooner.ValidatePostLoginRedirect("/dashboard?id=42", "https://app.example.com", nil)
	fmt.Println("safe:", safe, "err:", err)

	_, err = crooner.ValidatePostLoginRedirect("//evil.com", "", nil)
	fmt.Println("protocol-relative rejected:", err != nil)

	_, err = crooner.ValidatePostLoginRedirect("https://evil.com", "", nil)
	fmt.Println("absolute rejected:", err != nil)
	// Output:
	// safe: /dashboard?id=42 err: <nil>
	// protocol-relative rejected: true
	// absolute rejected: true
}

// ExampleIsAuthExemptPath demonstrates checking whether a request path
// should skip authentication.
func ExampleIsAuthExemptPath() {
	routes := &crooner.AuthRoutes{
		Login:    "/login",
		Logout:   "/logout",
		Callback: "/callback",
		AuthExempt: []string{
			"/health",
			"/public/",
		},
	}

	fmt.Println("/login:", crooner.IsAuthExemptPath("/login", routes))
	fmt.Println("/health:", crooner.IsAuthExemptPath("/health", routes))
	fmt.Println("/public/docs:", crooner.IsAuthExemptPath("/public/docs", routes))
	fmt.Println("/dashboard:", crooner.IsAuthExemptPath("/dashboard", routes))
	// Output:
	// /login: true
	// /health: true
	// /public/docs: true
	// /dashboard: false
}

// ExampleIsConfigError demonstrates using typed error checks to inspect
// errors returned by NewAuthConfig or other configuration functions.
func ExampleIsConfigError() {
	err := &crooner.ConfigError{Field: "IssuerURL", Reason: "missing required parameter"}

	fmt.Println("is config error:", crooner.IsConfigError(err))

	cfgErr, ok := crooner.AsConfigError(err)
	if ok {
		fmt.Println("field:", cfgErr.Field)
		fmt.Println("reason:", cfgErr.Reason)
	}
	// Output:
	// is config error: true
	// field: IssuerURL
	// reason: missing required parameter
}

// ExampleIsSessionError demonstrates using typed error checks to handle
// session errors from GetString, GetInt, and GetBool.
func ExampleIsSessionError() {
	err := &crooner.SessionError{Key: "user", Reason: crooner.ReasonNotFound}

	fmt.Println("is session error:", crooner.IsSessionError(err))

	sessErr, ok := crooner.AsSessionError(err)
	if ok {
		fmt.Println("key:", sessErr.Key)
		fmt.Println("reason:", sessErr.Reason)
	}
	// Output:
	// is session error: true
	// key: user
	// reason: not found
}

// ExampleIsChallengeError demonstrates checking for PKCE challenge errors.
func ExampleIsChallengeError() {
	err := &crooner.ChallengeError{Op: "GenerateCodeVerifier", Err: fmt.Errorf("entropy failure")}

	fmt.Println("is challenge error:", crooner.IsChallengeError(err))

	chErr, ok := crooner.AsChallengeError(err)
	if ok {
		fmt.Println("op:", chErr.Op)
	}
	// Output:
	// is challenge error: true
	// op: GenerateCodeVerifier
}

// ExampleSessionErrorResponse demonstrates creating a JSON-friendly
// response map from a session error.
func ExampleSessionErrorResponse() {
	err := &crooner.SessionError{Key: "user", Reason: crooner.ReasonNotFound}
	resp := crooner.SessionErrorResponse(err)

	fmt.Println("error:", resp["error"])
	fmt.Println("key:", resp["key"])
	fmt.Println("reason:", resp["reason"])
	// Output:
	// error: session_error
	// key: user
	// reason: not found
}

// ExampleAuthRoutes demonstrates defining the authentication routes and
// paths exempt from the auth-required middleware.
func ExampleAuthRoutes() {
	routes := &crooner.AuthRoutes{
		Login:    "/login",
		Logout:   "/logout",
		Callback: "/callback",
		AuthExempt: []string{
			"/health",
			"/api/public/",
		},
	}

	fmt.Println("login:", routes.Login)
	fmt.Println("exempt count:", len(routes.AuthExempt))
	// Output:
	// login: /login
	// exempt count: 2
}

// ExampleSecurityHeadersMiddleware demonstrates applying security-header
// middleware independently (without the full NewAuthConfig flow).
func ExampleSecurityHeadersMiddleware() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	handler := crooner.SecurityHeadersMiddleware(&crooner.SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'self'; img-src *",
		XFrameOptions:         "SAMEORIGIN",
	})(mux)
	_ = handler

	fmt.Println("security headers middleware applied")
	// Output:
	// security headers middleware applied
}

// ExampleIsConfigError_switch demonstrates a complete error-handling
// pattern using the typed errors returned by crooner functions.
func ExampleIsConfigError_switch() {
	// Simulate an error from NewAuthConfig validation.
	var err error = &crooner.ConfigError{
		Field:  "ClientID",
		Reason: "missing required parameter",
	}

	switch {
	case crooner.IsConfigError(err):
		cfgErr, _ := crooner.AsConfigError(err)
		fmt.Printf("config: field=%s reason=%s\n", cfgErr.Field, cfgErr.Reason)
	case crooner.IsAuthError(err):
		fmt.Println("auth error")
	case crooner.IsChallengeError(err):
		fmt.Println("challenge error")
	case crooner.IsSessionError(err):
		fmt.Println("session error")
	default:
		fmt.Println("unknown error")
	}

	// Check sentinel errors with errors.Is.
	stateErr := errors.Join(crooner.ErrInvalidStateFormat, fmt.Errorf("bad base64"))
	fmt.Println("is invalid state format:", errors.Is(stateErr, crooner.ErrInvalidStateFormat))
	// Output:
	// config: field=ClientID reason=missing required parameter
	// is invalid state format: true
}

# Crooner: Secure Azure AD Authentication for Go (Echo)

[![Go Reference](https://pkg.go.dev/badge/github.com/catgoose/crooner.svg)](https://pkg.go.dev/github.com/catgoose/crooner)

<!--toc:start-->

- [Crooner: Secure Azure AD Authentication for Go (Echo)](#crooner-secure-azure-ad-authentication-for-go-echo)
  - [About](#about)
  - [Features](#features)
  - [Installation](#installation)
  - [Quick Start Example (Full, Generic)](#quick-start-example-full-generic)
  - [Configuration](#configuration)
    - [Session Management (Best Practice)](#session-management-best-practice)
    - [Content Security Policy (CSP) and Security Headers](#content-security-policy-csp-and-security-headers)
      - [Default Security Header Values](#default-security-header-values)
    - [Session Configuration: Functional Options](#session-configuration-functional-options)
      - [Available Options](#available-options)
      - [Example Usage](#example-usage)
  - [Advanced Usage](#advanced-usage)
    - [Customizing SCS Config](#customizing-scs-config)
    - [Custom SessionManager](#custom-sessionmanager)
  - [Security Best Practices](#security-best-practices)
  - [Session Lifetime Recommendations](#session-lifetime-recommendations)
    - [Example: Setting Session Lifetime](#example-setting-session-lifetime)
  - [Contributing](#contributing)
  - [License](#license)
  <!--toc:end-->

## About

![image](https://github.com/catgoose/screenshots/blob/fb17ed7cd8e989691447b0e7a755d93a677abbfd/crooner/crooner.png)

Ever want to authenticate with Azure in your Go project but MSAL has no
examples for a hosted HTTP service: <https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/468>

Crooner is a Go library for secure, modern Azure AD authentication in Echo web apps. It provides pluggable session management, secure defaults, and easy integration with Azure OIDC/PKCE flows.

## Features

- **Azure AD PKCE/OIDC login**
- **Pluggable session management** (SCS, custom)
- **Configurable Content Security Policy (CSP)**
- **Secure, non-guessable session cookies**
- **Designed for Echo, but extensible**

## Installation

```bash
go get github.com/catgoose/crooner@latest
```

## Quick Start Example (Full, Generic)

```go
package main

import (
 "context"
 "fmt"
 "log"
 "os"
 "time"

 crooner "github.com/catgoose/crooner"
 "github.com/labstack/echo/v4"
)

type AppConfig struct {
 SessionSecret string
 AppName       string
 CroonerConfig *crooner.AuthConfigParams
 SessionMgr    crooner.SessionManager
}

func LoadAppConfig() (*AppConfig, error) {
 // Load secrets/config from environment variables or your preferred config system
 secret := os.Getenv("SESSION_SECRET")
 if secret == "" {
  return nil, fmt.Errorf("SESSION_SECRET is required")
 }
 appName := "myApp" // or load from env/config

 // Fill in your Azure AD and Crooner config
 croonerConfig := &crooner.AuthConfigParams{
  ClientID:          os.Getenv("AZURE_CLIENT_ID"),
  ClientSecret:      os.Getenv("AZURE_CLIENT_SECRET"),
  TenantID:          os.Getenv("AZURE_TENANT_ID"),
  RedirectURL:       os.Getenv("AZURE_REDIRECT_URL"),
  LogoutURLRedirect: os.Getenv("AZURE_LOGOUT_REDIRECT_URL"),
  LoginURLRedirect:  os.Getenv("AZURE_LOGIN_REDIRECT_URL"),
  AuthRoutes: &crooner.AuthRoutes{
   Login:    "/login",
   Logout:   "/logout",
   Callback: "/callback",
  },
  SecurityHeaders: &crooner.SecurityHeadersConfig{
   ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://login.microsoftonline.com;",
   XFrameOptions:           "DENY",
   XContentTypeOptions:     "nosniff",
   ReferrerPolicy:          "strict-origin-when-cross-origin",
   XXSSProtection:          "1; mode=block",
   StrictTransportSecurity: "max-age=63072000; includeSubDomains; preload", // set only if HTTPS
  },
  // ...other config as needed...
 }

 return &AppConfig{
  SessionSecret: secret,
  AppName:       appName,
  CroonerConfig: croonerConfig,
 }, nil
}

func main() {
 appConfig, err := LoadAppConfig()
 if err != nil {
  log.Fatalf("failed to load app config: %v", err)
 }

 e := echo.New()

 // --- Session Management with Functional Options ---
 sessionMgr, scsMgr, err := crooner.NewSCSManager(
  crooner.WithPersistentCookieName(appConfig.SessionSecret, appConfig.AppName),
  crooner.WithLifetime(12*time.Hour),
  crooner.WithCookieDomain("example.com"), // optional
  // ...add other options as needed
 )
 if err != nil {
  log.Fatalf("failed to initialize session manager: %v", err)
 }
 e.Use(echo.WrapMiddleware(scsMgr.LoadAndSave))
 appConfig.SessionMgr = sessionMgr
 appConfig.CroonerConfig.SessionMgr = sessionMgr

 // --- Crooner Auth Setup ---
 ctx := context.Background()
 if err := crooner.NewAuthConfig(ctx, e, appConfig.CroonerConfig); err != nil {
  log.Fatalf("failed to initialize Crooner authentication: %v", err)
 }

 // --- Your routes here ---
 e.GET("/", func(c echo.Context) error {
  return c.String(200, "Hello, Crooner!")
 })

 // Start server
 port := os.Getenv("PORT")
 if port == "" {
  port = "8080"
 }
 e.Logger.Fatal(e.Start(":" + port))
}
```

---

## Configuration

### Session Management (Best Practice)

- Use a strong, random `SESSION_SECRET` (set via env/config)
- Use a unique `AppName` per app
- Generate the cookie name with `crooner.PersistentCookieSuffix(secret, appName)`
- Use `crooner.DefaultSecureSessionConfig()` for secure defaults. To set a persistent, non-guessable cookie name, use `crooner.PersistentCookieSuffix(secret, appName)` and assign it to the config's CookieName field.

### Content Security Policy (CSP) and Security Headers

You can configure all major security headers via `SecurityHeadersConfig`. If a field is empty, a secure default will be used.

```go
params := &crooner.AuthConfigParams{
 // ... other config ...
 SecurityHeaders: &crooner.SecurityHeadersConfig{
  ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://login.microsoftonline.com;",
  XFrameOptions:           "DENY",
  XContentTypeOptions:     "nosniff",
  ReferrerPolicy:          "strict-origin-when-cross-origin",
  XXSSProtection:          "1; mode=block",
  StrictTransportSecurity: "max-age=63072000; includeSubDomains; preload", // set only if HTTPS
 },
}
```

#### Default Security Header Values

| Header                    | Default Value                     |
| ------------------------- | --------------------------------- |
| Content-Security-Policy   | `default-src 'self'`              |
| X-Frame-Options           | `DENY`                            |
| X-Content-Type-Options    | `nosniff`                         |
| Referrer-Policy           | `strict-origin-when-cross-origin` |
| X-XSS-Protection          | `1; mode=block`                   |
| Strict-Transport-Security | _(not set by default)_            |

- To override a header, set the corresponding field in `SecurityHeadersConfig`.
- `Strict-Transport-Security` should only be set if your app is always served over HTTPS.

### Session Configuration: Functional Options

Crooner uses idiomatic Go functional options for session configuration. You can compose these options to customize session behavior.

#### Available Options

- `WithPersistentCookieName(secret, appName string)` — Sets a non-guessable, persistent cookie name using your secret and app name (recommended for production).
- `WithCookieName(name string)` — Sets a custom cookie name.
- `WithCookieDomain(domain string)` — Sets the cookie domain.
- `WithCookiePath(path string)` — Sets the cookie path.
- `WithCookieSecure(secure bool)` — Sets the Secure flag.
- `WithCookieHTTPOnly(httpOnly bool)` — Sets the HttpOnly flag.
- `WithCookieSameSite(sameSite http.SameSite)` — Sets the SameSite mode.
- `WithLifetime(lifetime time.Duration)` — Sets the session lifetime.
- `WithStore(store scs.Store)` — Sets a custom session store backend (e.g., Redis).

#### Example Usage

```go
sessionMgr, scsMgr, err := crooner.NewSCSManager(
 crooner.WithPersistentCookieName(appConfig.SessionSecret, appConfig.AppName),
 crooner.WithLifetime(12*time.Hour),
 crooner.WithCookieDomain("example.com"),
 // Add other options as needed
)
if err != nil {
 log.Fatalf("failed to initialize session manager: %v", err)
}
```

- You can combine as many options as you need.
- If you use both `WithPersistentCookieName` and `WithCookieName`, the last one wins.
- All options have secure defaults if not set.

## Advanced Usage

### Customizing SCS Config

```go
cfg := crooner.DefaultSecureSessionConfig()
suffix := crooner.PersistentCookieSuffix(appConfig.SessionSecret, appConfig.AppName)
cfg.CookieName = "crooner-" + suffix
cfg.Lifetime = 7 * 24 * time.Hour // 7 days
cfg.CookieDomain = ".example.com"
cfg.CookieSameSite = http.SameSiteStrictMode
cfg.CookieSecure = true // (default is true)
// Advanced: use Redis or another backend
// cfg.Store = myRedisStore
sessionMgr, scsMgr, err := crooner.NewSCSManagerWithConfig(cfg)
if err != nil {
 log.Fatalf("failed to initialize session manager: %v", err)
}
```

### Custom SessionManager

- Implement the `SessionManager` interface for your own backend (e.g., DB, Redis, etc.)

## Security Best Practices

- Use a strong, random session secret (32+ bytes)
- Use a unique, non-guessable cookie name per app (`crooner-<hash>`, not predictable)
- Rotate the session secret to force logout of all users
- Use HTTPS, HttpOnly, SameSite, Secure cookies
- Configure CSP for your frontend’s needs

## Session Lifetime Recommendations

The session lifetime determines how long a user stays logged in before needing to re-authenticate. Choose a value that balances security and user experience:

- **8–12 hours:** Best for sensitive apps (admin, finance, healthcare)
- **12–24 hours:** Good default for most business apps
- **48 hours (2 days):** User-friendly for apps where convenience is important
- **7+ days:** Only for "remember me" features (use with caution)

**Shorter lifetimes are more secure, longer lifetimes are more convenient.**

### Example: Setting Session Lifetime

```go
cfg := crooner.DefaultSecureSessionConfig()
suffix := crooner.PersistentCookieSuffix(appConfig.SessionSecret, appConfig.AppName)
cfg.CookieName = "crooner-" + suffix
cfg.Lifetime = 24 * time.Hour // 1 day is a good default
// For more convenience:
// cfg.Lifetime = 48 * time.Hour // 2 days
```

- Always destroy the session on logout.
- Regenerate the session on login or privilege change.

## Contributing

PRs and issues welcome! Please open an issue to discuss major changes first.

---

## License

MIT

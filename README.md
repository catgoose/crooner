# Crooner: Secure Azure AD Authentication for Go (Echo)

<!--toc:start-->

- [Crooner: Secure Azure AD Authentication for Go (Echo)](#crooner-secure-azure-ad-authentication-for-go-echo)
  - [About](#about)
  - [Features](#features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
    - [1. Set Up Your Config (config.go)](#1-set-up-your-config-configgo)
    - [2. Set Up Session Management (router.go)](#2-set-up-session-management-routergo)
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
  - [FAQ / Troubleshooting](#faq-troubleshooting)
  - [Contributing](#contributing)
  - [License](#license)
  <!--toc:end-->

## About

![image](https://github.com/catgoose/screenshots/blob/fb17ed7cd8e989691447b0e7a755d93a677abbfd/crooner/crooner.png)

Ever want to authenticate with Azure in your Go project but MSAL has no
examples for a hosted HTTP service: <https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/468>

Crooner is a Go library for secure, modern Azure AD authentication in Echo web apps. It provides pluggable session management, secure defaults, and easy integration with Azure OIDC/PKCE flows.

---

## Features

- **Azure AD PKCE/OIDC login**
- **Pluggable session management** (SCS, custom)
- **Configurable Content Security Policy (CSP)**
- **Secure, non-guessable session cookies**
- **Designed for Echo, but extensible**

---

## Installation

```bash
go get github.com/catgoose/crooner@latest
```

---

## Quick Start

### 1. Set Up Your Config (config.go)

```go
import (
 crooner "github.com/catgoose/crooner"
 "github.com/catgoose/dio"
 // ...
)

type AppConfig struct {
 // ... other fields ...
 SessionSecret string
 AppName       string
}

func LoadAppConfig() (*AppConfig, error) {
 // ... load other config ...
 secret, err := dio.Env("SESSION_SECRET")
 if err != nil {
  return nil, err
 }
 appName := "tradesnewsletter" // or get from env/config if desired
 // ...
 return &AppConfig{
  // ...
  SessionSecret: secret,
  AppName:       appName,
 }, nil
}
```

### 2. Set Up Session Management (router.go)

```go
import (
 crooner "github.com/catgoose/crooner"
 // ...
)

func setupAuth(e *echo.Echo, appConfig *config.AppConfig) {
 suffix := crooner.PersistentCookieSuffix(appConfig.SessionSecret, appConfig.AppName)
 cfg := crooner.DefaultSecureSessionConfig()
 cfg.CookieName = "crooner-" + suffix
 cfg.CookieDomain = "example.com" // optional
 cfg.Lifetime = 12 * time.Hour    // example: shorter session
 // ... set any other options as needed
 sessionMgr, scsMgr := crooner.NewSCSManagerWithConfig(cfg)
 e.Use(echo.WrapMiddleware(scsMgr.LoadAndSave))
 appConfig.SessionMgr = sessionMgr
 appConfig.CroonerConfig.SessionMgr = sessionMgr
 ctx := context.Background()
 if err := crooner.NewAuthConfig(ctx, e, appConfig.CroonerConfig); err != nil {
  panic(fmt.Errorf("failed to initialize Crooner authentication: %v", err))
 }
}
```

---

## Configuration

### Session Management (Best Practice)

- Use a strong, random `SESSION_SECRET` (set via env/config)
- Use a unique `AppName` per app
- Generate the cookie name with `crooner.PersistentCookieSuffix(secret, appName)`
- Use `crooner.DefaultSCSFactoryConfigWithSuffix(suffix)` for secure defaults

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

---

## Advanced Usage

### Customizing SCS Config

```go
cfg := crooner.DefaultSCSFactoryConfigWithSuffix(suffix)
cfg.Lifetime = 7 * 24 * time.Hour // 7 days
cfg.CookieDomain = ".example.com"
cfg.CookieSameSite = http.SameSiteStrictMode
cfg.CookieSecure = true // (default is true)
// Advanced: use Redis or another backend
// cfg.Store = myRedisStore
sessionMgr, scsMgr := crooner.NewSCSManagerWithConfig(cfg)
```

### Custom SessionManager

- Implement the `SessionManager` interface for your own backend (e.g., DB, Redis, etc.)

---

## Security Best Practices

- Use a strong, random session secret (32+ bytes)
- Use a unique, non-guessable cookie name per app (`crooner-<hash>`, not predictable)
- Rotate the session secret to force logout of all users
- Use HTTPS, HttpOnly, SameSite, Secure cookies
- Configure CSP for your frontend’s needs

---

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

---

## FAQ / Troubleshooting

- **Why do I see multiple cookies?**
  - Only the cookie matching your current config is used. Use a persistent, secret-derived name for production.
- **Why are users logged out after a restart?**
  - If the cookie name changes, users lose their session. Use a persistent name as shown above.
- **How do I force logout all users?**
  - Rotate the session secret.
- **How do I allow inline scripts/styles?**
  - Relax your CSP as shown above.

---

## Contributing

PRs and issues welcome! Please open an issue to discuss major changes first.

---

## License

MIT

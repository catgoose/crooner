# 🎩 Crooner: You Gotta Be Right Next to Me for It to Look Real, Baby

[![Go Reference](https://pkg.go.dev/badge/github.com/catgoose/crooner.svg)](https://pkg.go.dev/github.com/catgoose/crooner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![image](https://github.com/catgoose/screenshots/blob/fb17ed7cd8e989691447b0e7a755d93a677abbfd/crooner/crooner.png)

<!--toc:start-->
- [🎩 Crooner: You Gotta Be Right Next to Me for It to Look Real, Baby](#🎩-crooner-you-gotta-be-right-next-to-me-for-it-to-look-real-baby)
  - [What Is This? Why Do People Hate It?](#what-is-this-why-do-people-hate-it)
  - [Features (Don't Try to Steal My Decals)](#features-dont-try-to-steal-my-decals)
  - [Installation (You Gotta Give!)](#installation-you-gotta-give)
  - [Quick Start Example (You Gotta Be Right Next to Me)](#quick-start-example-you-gotta-be-right-next-to-me)
  - [Configuration (Don't Let Them Make It Look Fake)](#configuration-dont-let-them-make-it-look-fake)
    - [Session Management (Best Practice)](#session-management-best-practice)
    - [Content Security Policy (CSP) and Security Headers](#content-security-policy-csp-and-security-headers)
      - [Default Security Header Values](#default-security-header-values)
    - [Session Configuration: Functional Options](#session-configuration-functional-options)
      - [Available Options](#available-options)
      - [Example Usage](#example-usage)
  - [Advanced Usage (You Gotta Be Right Next to Me)](#advanced-usage-you-gotta-be-right-next-to-me)
    - [Custom SessionManager](#custom-sessionmanager)
      - [Example: Redis Implementation](#example-redis-implementation)
  - [Security Best Practices (Don't Let Them Make It Look Fake)](#security-best-practices-dont-let-them-make-it-look-fake)
  - [Session Lifetime Recommendations (How Long's the Set?)](#session-lifetime-recommendations-how-longs-the-set)
  - [Setting Session Lifetime](#setting-session-lifetime)
    - [Examples](#examples)
  - [Retrieving the Session Cookie Name](#retrieving-the-session-cookie-name)
    - [Type-Specific Session Helper Functions](#type-specific-session-helper-functions)
      - [Available Helpers](#available-helpers)
      - [Usage Example](#usage-example)
    - [Error Types](#error-types)
  - [Questions? PRs? Hecklers?](#questions-prs-hecklers)
  - [License](#license)
  - [Driving Crooner Authentication Flow (Don't Let Them Make It Look Fake)](#driving-crooner-authentication-flow-dont-let-them-make-it-look-fake)
    - [How the Crooner Keeps You on the Road](#how-the-crooner-keeps-you-on-the-road)
      - [Example: The Real Crooner Flow](#example-the-real-crooner-flow)
      - [Note for Development (Don’t Let the Session Look Fake)](#note-for-development-dont-let-the-session-look-fake)
<!--toc:end-->

> Fuck! He's trying to steal my decals!
> Fuck! They're trying to make it look fake! Goddammit!
> You gotta give!
> The hat and the cigar. You're driving with the Driving Crooner, baby.

## What Is This? Why Do People Hate It?

I don't know. Some people hate this, James. I don't know what it is, but they fuckin' hate it. There's people that wanna kill me, James. But I gotta figure out how to make money on this thing. It's simply too good. Crooner is for Go web apps using Echo, and it's the real deal. Not like those other guys, with their fake decals and their fake logins. This is the real Crooner. The hat and the cigar.

Ever want to authenticate with Azure in your Go project but MSAL has no examples for a hosted HTTP service? [MSAL Issue #468](https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/468)

Crooner is a Go library for secure, modern Azure AD authentication in Echo web apps. It provides pluggable session management, secure defaults, and easy integration with Azure OIDC/PKCE flows.

## Features (Don't Try to Steal My Decals)

- **Azure AD PKCE/OIDC login**
- **Pluggable session management** (SCS, custom)
- **Configurable Content Security Policy (CSP)**
- **Secure, non-guessable session cookies**
- **Designed for Echo, but extensible**
- **Preserves original URLs (including query strings) through login and callback**
- **Reverse proxy friendly authentication flow**
- **Automatic recovery from lost session state (e.g., after server restart)**

## Installation (You Gotta Give!)

```bash
go get github.com/catgoose/crooner@latest
```

## Quick Start Example (You Gotta Be Right Next to Me)

Here's how you get the show on the road:

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
   ContentSecurityPolicy:   "img-src 'self' data: https://login.microsoftonline.com;",
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

 ctx := context.Background()
 if err := crooner.NewAuthConfig(ctx, e, appConfig.CroonerConfig); err != nil {
  log.Fatalf("failed to initialize Crooner authentication: %v", err)
 }

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

## Configuration (Don't Let Them Make It Look Fake)

### Session Management (Best Practice)

- Use a strong, random `SESSION_SECRET` (set via env/config)
- Use a unique `AppName` per app
- Set a persistent, non-guessable cookie name using `crooner.WithPersistentCookieName(secret, appName)` when creating your session manager:

  ```go
  sessionMgr, scsMgr, err := crooner.NewSCSManager(
   crooner.WithPersistentCookieName(secret, appName),
   // ...other options...
  )

  ```

- Secure defaults are applied automatically by `NewSCSManager`. You only need to use advanced config if you have special requirements.

### Content Security Policy (CSP) and Security Headers

You can configure all major security headers via `SecurityHeadersConfig`. If a field is empty, a secure default will be used.

```go
params := &crooner.AuthConfigParams{
 // ... other config ...
 SecurityHeaders: &crooner.SecurityHeadersConfig{
  ContentSecurityPolicy:   "img-src 'self' data: https://login.microsoftonline.com;",
  XFrameOptions:           "DENY",
  XContentTypeOptions:     "nosniff",
  ReferrerPolicy:          "strict-origin-when-cross-origin",
  XXSSProtection:          "1; mode=block",
  StrictTransportSecurity: "max-age=63072000; includeSubDomains; preload", // set only if HTTPS
 },
}
```

The Crooner don't fake who's in the car. You pick which ID token claim rides shotgun as the session user—default's `"email"`. If your Azure AD app ain't giving you email, use `"preferred_username"` or `"upn"`:

```go
params := &crooner.AuthConfigParams{
 // ... other config ...
 UserClaim: "preferred_username", // or "upn" for some tenants
}
```

Crooner tries your claim first, then falls back to `email` and `preferred_username` so nobody gets left at the curb.

#### Default Security Header Values

| Header                     | Default Value                      |
|----------------------------|------------------------------------|
| Content-Security-Policy    | `default-src 'self'`               |
| X-Frame-Options            | `DENY`                             |
| X-Content-Type-Options     | `nosniff`                          |
| Referrer-Policy            | `strict-origin-when-cross-origin`  |
| X-XSS-Protection           | `1; mode=block`                    |
| Strict-Transport-Security  | _(not set by default)_             |

- To override a header, set the corresponding field in `SecurityHeadersConfig`.
- `Strict-Transport-Security` should only be set if your app is always served over HTTPS.

### Session Configuration: Functional Options

Crooner uses idiomatic Go functional options for session configuration. You can compose these options to customize session behavior.

#### Available Options

| Option                                             | Description                                                                                               |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `WithPersistentCookieName(secret, appName string)` | Sets a non-guessable, persistent cookie name using your secret and app name (recommended for production). |
| `WithCookieName(name string)`                      | Sets a custom cookie name.                                                                                |
| `WithCookieDomain(domain string)`                  | Sets the cookie domain.                                                                                   |
| `WithCookiePath(path string)`                      | Sets the cookie path.                                                                                     |
| `WithCookieSecure(secure bool)`                    | Sets the Secure flag.                                                                                     |
| `WithCookieHTTPOnly(httpOnly bool)`                | Sets the HttpOnly flag.                                                                                   |
| `WithCookieSameSite(sameSite http.SameSite)`       | Sets the SameSite mode.                                                                                   |
| `WithLifetime(lifetime time.Duration)`             | Sets the session lifetime.                                                                                |
| `WithStore(store scs.Store)`                       | Sets a custom session store backend (e.g., Redis).                                                        |

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

## Advanced Usage (You Gotta Be Right Next to Me)

If you need to fully customize the session config, you can use `crooner.DefaultSecureSessionConfig()` and then pass it to `crooner.NewSCSManagerWithConfig(cfg)`. This is for advanced use only.

Sometimes you don't need the full show—just "who's in the car." Use `crooner.RequireAuth(sessionMgr, routes)` as middleware: `e.Use(crooner.RequireAuth(sessionMgr, routes))` or slap it on a group. Only the real ones get through. No fake passengers, baby.

```go
cfg := crooner.DefaultSecureSessionConfig()
// Customize as needed
cfg.CookieName = "crooner-" + myCustomSuffix
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

#### Example: Redis Implementation

You can use any backend for session storage by implementing the `SessionManager` interface. Here is a basic example of how you might implement a Redis-backed session manager:

```go
package myapp

import (
 "context"
 "encoding/json"
 "github.com/catgoose/crooner"
 "github.com/go-redis/redis/v8"
 "github.com/labstack/echo/v4"
 "time"
)

type RedisSessionManager struct {
 Client *redis.Client
 Prefix string // optional, for namespacing session keys
 TTL    time.Duration
}

func (r *RedisSessionManager) sessionKey(c echo.Context, key string) string {
 // You can use a cookie, header, or other identifier for session scoping
 sessionID := c.Request().Header.Get("X-Session-ID") // Example only
 return r.Prefix + sessionID + ":" + key
}

func (r *RedisSessionManager) Get(c echo.Context, key string) (any, error) {
 ctx := c.Request().Context()
 val, err := r.Client.Get(ctx, r.sessionKey(c, key)).Result()
 if err == redis.Nil {
  return nil, nil
 } else if err != nil {
  return nil, err
 }
 var result any
 if err := json.Unmarshal([]byte(val), &result); err != nil {
  return nil, err
 }
 return result, nil
}

func (r *RedisSessionManager) Set(c echo.Context, key string, value any) error {
 ctx := c.Request().Context()
 data, err := json.Marshal(value)
 if err != nil {
  return err
 }
 return r.Client.Set(ctx, r.sessionKey(c, key), data, r.TTL).Err()
}

func (r *RedisSessionManager) Delete(c echo.Context, key string) error {
 ctx := c.Request().Context()
 return r.Client.Del(ctx, r.sessionKey(c, key)).Err()
}

func (r *RedisSessionManager) Clear(c echo.Context) error {
 // Implement logic to clear all session keys for the user/session
 return nil // Example: not implemented
}

func (r *RedisSessionManager) Invalidate(c echo.Context) error {
 // Implement logic to invalidate the session (e.g., delete all keys)
 return nil // Example: not implemented
}

func (r *RedisSessionManager) ClearInvalidate(c echo.Context) error {
 if err := r.Clear(c); err != nil {
  return err
 }
 return r.Invalidate(c)
}
```

To use your custom Redis session manager with Crooner:

```go
import (
 crooner "github.com/catgoose/crooner"
 "github.com/go-redis/redis/v8"
 "github.com/labstack/echo/v4"
 "time"
)

func main() {
 e := echo.New()
 redisClient := redis.NewClient(&redis.Options{
  Addr: "localhost:6379",
  // ...other options...
 })
 sessionMgr := &myapp.RedisSessionManager{
  Client: redisClient,
  Prefix: "crooner:",
  TTL:    24 * time.Hour,
 }
 croonerConfig := &crooner.AuthConfigParams{
  // ...other config...
  SessionMgr: sessionMgr,
 }
 // ...rest of your setup...
}
```

This approach allows you to use Redis (or any other backend) for session storage, as long as your implementation satisfies the `SessionManager` interface.

## Security Best Practices (Don't Let Them Make It Look Fake)

- Use a strong, random session secret (32+ bytes)
- Use a unique, non-guessable cookie name per app (`crooner-<hash>`, not predictable)
- Rotate the session secret to force logout of all users
- Use HTTPS, HttpOnly, SameSite, Secure cookies
- Configure CSP for your frontend’s needs

## Session Lifetime Recommendations (How Long's the Set?)

The session lifetime determines how long a user stays logged in before needing to re-authenticate. Choose a value that balances security and user experience:

- **8–12 hours:** Best for sensitive apps (admin, finance, healthcare)
- **12–24 hours:** Good default for most business apps
- **48 hours (2 days):** User-friendly for apps where convenience is important
- **7+ days:** Only for "remember me" features (use with caution)

**Shorter lifetimes are more secure, longer lifetimes are more convenient.**

## Setting Session Lifetime

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

## Retrieving the Session Cookie Name

When you create a session manager using crooner, the session cookie name may be generated dynamically (for example, using `WithPersistentCookieName`). To retrieve the actual cookie name for use in your application (such as in middleware), use the `GetCookieName()` method on the session manager:

```go
sessionMgr, _, err := crooner.NewSCSManager(
 crooner.WithPersistentCookieName(appConfig.SessionSecret, appConfig.AppName),
 crooner.WithLifetime(24*time.Hour),
)
if err != nil {
 // handle error
}
cookieName := sessionMgr.GetCookieName()

// Use cookieName in your middleware setup
// e.g., e.Use(middleware.AzureClaims(cookieName))
```

This ensures your middleware and other components always use the correct session cookie name, even if it is generated or hashed internally.

### Type-Specific Session Helper Functions

Crooner provides type-specific helper functions for retrieving session values in a type-safe way. These helpers work with any implementation of the `SessionManager` interface and return an error if the value is missing or not of the expected type.

#### Available Helpers

- `GetString(sm SessionManager, c echo.Context, key string) (string, error)`
- `GetInt(sm SessionManager, c echo.Context, key string) (int, error)`
- `GetBool(sm SessionManager, c echo.Context, key string) (bool, error)`

#### Usage Example

```go
import (
 crooner "github.com/catgoose/crooner"
 "github.com/labstack/echo/v4"
)

func myHandler(c echo.Context) error {
 // Assume sessionMgr is your SessionManager implementation
 username, err := crooner.GetString(sessionMgr, c, "username")
 if err != nil {
  return c.String(401, "Unauthorized")
 }
 return c.String(200, "Hello, "+username)
}
```

These helpers provide robust error handling and work with any backend that implements the `SessionManager` interface.

### Error Types

When something goes wrong, the Crooner don't leave you guessing. We use typed errors so you can check with `errors.As` or `errors.Is`:

- **ConfigError** — something's wrong with the setup (e.g. from `NewAuthConfig`). Check with `crooner.IsConfigError(err)` or `errors.As(err, &cfgErr)` where `var cfgErr *crooner.ConfigError`.
- **AuthError** — token exchange or ID token didn't check out. Check with `crooner.IsAuthError(err)` or `crooner.AsAuthError(err)`.
- **ChallengeError** — PKCE or state got messed up. Check with `crooner.IsChallengeError(err)` or `crooner.AsChallengeError(err)`.
- **SessionError** — session get/set or wrong type (e.g. from `GetString`, `GetInt`, `GetBool`). Check with `crooner.IsSessionError(err)` or `crooner.AsSessionError(err)`.
- **State decode errors** — invalid OAuth state (bad base64 or malformed payload). Use `errors.Is(err, crooner.ErrInvalidStateFormat)` or `errors.Is(err, crooner.ErrInvalidStateData)`.

Don't let them make it look fake. Handle your errors.

## Driving Crooner Authentication Flow (Don't Let Them Make It Look Fake)

You ever try to log in behind a reverse proxy and it just dumps you on the wrong page? Not with the Driving Crooner, baby. This authentication flow is so real, it’ll keep your decals safe and your redirects looking legit—even if some guy in a hot dog suit is trying to make it look fake.

### How the Crooner Keeps You on the Road

1. **You try to visit a protected page**
   - The Crooner checks your credentials. If you’re not logged in, he throws you in the sidecar and redirects you to `/login?redirect=<your real destination, decals and all>`. That means the full path, query string, the works. No fake detours.
2. **Login Handler: The Hat and the Cigar**
   - Crooner encodes a secret state and your original destination into a base64-encoded package, stashes it in your session, and sends you off to the OAuth provider. Nobody’s stealing your spot in line.
3. **Callback: You Gotta Be Right Next to Me**
   - After you sign in, the OAuth provider sends you back to `/callback` with your state. Crooner decodes it, checks your credentials, and puts you right back where you started—no matter how many fake login pages you drove through.
4. **If the Session’s Gone (You Hit a Pothole)**
   - Maybe you live reloaded, maybe the server restarted, maybe you just got bumped out by a fish. If the session state is missing or doesn’t match, Crooner doesn’t freak out. He just restarts the login flow, keeping your original destination safe. No “Invalid state” errors, no fake-outs.

#### Example: The Real Crooner Flow

1. You hit `/dashboard?id=42` (not logged in)
2. Crooner sends you to `/login?redirect=/dashboard?id=42` (decals intact)
3. You get sent to the OAuth provider with a state that’s got your back
4. After login, you’re back at `/callback?...&state=...`
5. Crooner decodes the state and puts you right back at `/dashboard?id=42`—no detours, no fake logins

If you hit a pothole (like a live reload), Crooner just restarts the login flow. You never see an error, you never lose your place. That’s the real deal.

#### Note for Development (Don’t Let the Session Look Fake)

If you’re using an in-memory session store and you restart the server, your session’s gone. But Crooner’s got you: he’ll just restart the login flow and keep you moving. For production, use a persistent session store (Redis, SQLite, whatever keeps your decals safe).


## Questions? PRs? Hecklers?

Open an issue, send a PR, or just shout “Crooner!” into the night. We'll hear you. But you gotta be right next to me for it to look real.

When I was a kid, I fell into a river and a fish bumped me out. I was supposed to die. But a fish bumped me out with its nose. That was the earth telling me I'm supposed to do something great. And I know that's the Driving Crooner. It has to be. You know what I mean, James?

## License

MIT, baby! Use it, fork it, remix it—just don't try to make it look fake.

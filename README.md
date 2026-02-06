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
  - [Retrieving the Session Cookie Name](#retrieving-the-session-cookie-name)
    - [Type-Specific Session Helper Functions](#type-specific-session-helper-functions)
      - [Available Helpers](#available-helpers)
      - [Usage Example](#usage-example)
    - [Error Types](#error-types)
  - [Development and the Makefile (You Gotta Be Right Next to Me)](#development-and-the-makefile-you-gotta-be-right-next-to-me)
    - [About the example errors in docs](#about-the-example-errors-in-docs)
  - [Testing (You Gotta Be Right Next to Me)](#testing-you-gotta-be-right-next-to-me)
  - [Driving Crooner Authentication Flow (Don't Let Them Make It Look Fake)](#driving-crooner-authentication-flow-dont-let-them-make-it-look-fake)
    - [How the Crooner Keeps You on the Road](#how-the-crooner-keeps-you-on-the-road)
      - [Example: The Real Crooner Flow](#example-the-real-crooner-flow)
      - [Note for Development (Don’t Let the Session Look Fake)](#note-for-development-dont-let-the-session-look-fake)
  - [Questions? PRs? Hecklers?](#questions-prs-hecklers)
  - [License](#license)
  <!--toc:end-->

> Fuck! He's trying to steal my decals!
> Fuck! They're trying to make it look fake! Goddammit!
> You gotta give!
> The hat and the cigar. You're driving with the Driving Crooner, baby.

Crooner is an Azure AD OIDC/OAuth2 client for Go Echo apps. It handles PKCE login, callbacks, and session management with pluggable backends and secure defaults.

## What Is This? Why Do People Hate It?

I don't know. Some people hate this, James. I don't know what it is, but they fuckin' hate it. There's people that wanna kill me, James. But I gotta figure out how to make money on this thing. It's simply too good. Crooner is for Go web apps using Echo, and it's the real deal. Not like those other guys, with their fake decals and their fake logins. This is the real Crooner. The hat and the cigar.

Ever want to authenticate with Azure in your Go project but MSAL has no examples for a hosted HTTP service? [MSAL Issue #468](https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/468)

## Features (Don't Try to Steal My Decals)

What you get when you ride with the Crooner—none of this fake stuff:

- **Azure AD PKCE/OIDC login** — the hat and the cigar
- **Pluggable session management** (SCS, custom) — you pick who's in the car
- **Configurable Content Security Policy (CSP)** — don't let them make it look fake
- **Secure, non-guessable session cookies** — no decal theft
- **Designed for Echo, but extensible** — right next to me, baby
- **Preserves original URLs (including query strings) through login and callback** — your destination stays real
- **Reverse proxy friendly authentication flow** — keeps you on the road
- **Automatic recovery from lost session state** (e.g., after server restart) — hit a pothole? Crooner gets you back

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

Don't let them make it look fake. Do it right:

- Use a strong, random `SESSION_SECRET` (set via env/config)—you gotta give.
- Use a unique `AppName` per app. No sharing decals.
- Set a persistent, non-guessable cookie name using `crooner.WithPersistentCookieName(secret, appName)` when creating your session manager:

  ```go
  sessionMgr, scsMgr, err := crooner.NewSCSManager(
  	crooner.WithPersistentCookieName(secret, appName),
  	// ...other options...
  )

  ```

- `NewSCSManager` applies secure defaults so the show looks real. Only reach for advanced config when you've got special requirements.

### Content Security Policy (CSP) and Security Headers

Configure your security headers via `SecurityHeadersConfig`. Empty field? Crooner slaps a secure default on it so nobody makes it look fake.

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

| Header                    | Default Value                     |
| ------------------------- | --------------------------------- |
| Content-Security-Policy   | `default-src 'self'`              |
| X-Frame-Options           | `DENY`                            |
| X-Content-Type-Options    | `nosniff`                         |
| Referrer-Policy           | `strict-origin-when-cross-origin` |
| X-XSS-Protection          | `1; mode=block`                   |
| Strict-Transport-Security | _(not set by default)_            |

- Override a header by setting the field in `SecurityHeadersConfig`.
- Set `Strict-Transport-Security` only when your app is always served over HTTPS—otherwise you're just pretending, James.

### Session Configuration: Functional Options

Crooner uses idiomatic Go functional options for session config. Compose 'em how you want—you gotta be right next to me for it to look real.

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

- Combine as many options as you need. No fake limits.
- If you use both `WithPersistentCookieName` and `WithCookieName`, the last one wins—don't let 'em confuse the decals.
- Not set? Secure defaults. The Crooner don't leave the car open.

## Advanced Usage (You Gotta Be Right Next to Me)

Need to run the whole show your way? Use `crooner.DefaultSecureSessionConfig()` and pass it to `crooner.NewSCSManagerWithConfig(cfg)`. Advanced only—don't reach for this unless you really gotta.

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

Implement the `SessionManager` interface and bring your own ride—DB, Redis, whatever keeps your decals safe.

#### Example: Redis Implementation

Any backend works as long as it implements `SessionManager`. Here's how you might do it with Redis so the session stays real:

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

That's it. Redis—or any backend that satisfies `SessionManager`—and you're driving with the Crooner. No fake storage, baby.

## Security Best Practices (Don't Let Them Make It Look Fake)

They're gonna try to make it look fake. Don't let 'em:

- Use a strong, random session secret (32+ bytes)—you gotta give.
- Use a unique, non-guessable cookie name per app (`crooner-<hash>`, not something they can guess)
- Rotate the session secret when you need everybody out—forces logout, keeps decals safe
- HTTPS, HttpOnly, SameSite, Secure cookies. The real deal.
- Configure CSP for your frontend’s needs
- Don't give the crowd your dirty laundry—keep `ErrorConfig.ShowDetails` **false** in production so internal error details (OAuth, ID token, etc.) never hit the client. They'll try to make it look fake.
- Behind a reverse proxy (TLS termination)? You gotta trust proxy headers (`X-Forwarded-Proto`, `X-Forwarded-Host`) so your app gets the right `Scheme` and `Host` for redirects and HSTS. Otherwise it looks fake, baby.

## Session Lifetime Recommendations (How Long's the Set?)

How long's the set before they gotta show their face again? Pick something that doesn't make it look fake:

- **8–12 hours:** Sensitive stuff—admin, finance, healthcare. Short set, real security.
- **12–24 hours:** Good default for most business apps. Right next to me, baby.
- **48 hours (2 days):** When convenience matters and you're okay with a longer ride
- **7+ days:** "Remember me" only—use with caution or they'll think it's fake

Shorter set = more secure. Longer set = more convenient. You gotta give somewhere.

## Setting Session Lifetime

```go
cfg := crooner.DefaultSecureSessionConfig()
suffix := crooner.PersistentCookieSuffix(appConfig.SessionSecret, appConfig.AppName)
cfg.CookieName = "crooner-" + suffix
cfg.Lifetime = 24 * time.Hour // 1 day is a good default
// For more convenience:
// cfg.Lifetime = 48 * time.Hour // 2 days
```

- Destroy the session on logout. No ghost passengers.
- Regenerate the session on login or privilege change—fresh decals.
- The logout route is **POST** only so some fake link can't boot you. Use a form with `method="post"` and `action="/logout"` (or a button that submits it) for your logout button.

## Retrieving the Session Cookie Name

Sometimes the cookie name is generated for you (e.g. with `WithPersistentCookieName`). You gotta know the real name for middleware and the rest of your app. Use `GetCookieName()` on the session manager:

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

Then your middleware and everything else use the real cookie name—no guessing, no fake decals.

### Type-Specific Session Helper Functions

Crooner's got type-specific helpers so you pull session values the right way—no fake types. They work with any `SessionManager` and return an error if the value's missing or wrong. You gotta be right next to me for it to look real.

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

Robust error handling, any backend that implements `SessionManager`—the real deal, baby.

Crooner does **not** store the OAuth2 access token or refresh token in the session by default. Only the user identifier (and any claims you map via `SessionValueClaims`) are persisted. If your app needs to call APIs on behalf of the user, you must persist tokens yourself (e.g. in session or a store) in a custom callback or post-login step.

### Error Types

When something goes wrong, the Crooner don't leave you guessing. We use typed errors so you can check with `errors.As` or `errors.Is`:

- **ConfigError** — something's wrong with the setup (e.g. from `NewAuthConfig`). Check with `crooner.IsConfigError(err)` or `errors.As(err, &cfgErr)` where `var cfgErr *crooner.ConfigError`.
- **AuthError** — token exchange or ID token didn't check out. Check with `crooner.IsAuthError(err)` or `crooner.AsAuthError(err)`.
- **ChallengeError** — PKCE or state got messed up. Check with `crooner.IsChallengeError(err)` or `crooner.AsChallengeError(err)`.
- **SessionError** — session get/set or wrong type (e.g. from `GetString`, `GetInt`, `GetBool`). Check with `crooner.IsSessionError(err)` or `crooner.AsSessionError(err)`.
- **State decode errors** — invalid OAuth state (bad base64 or malformed payload). Use `errors.Is(err, crooner.ErrInvalidStateFormat)` or `errors.Is(err, crooner.ErrInvalidStateData)`.

That's for when you're driving the Crooner yourself—your code, your handlers. When the Crooner hits a pothole on login, callback, or logout, he don't hand you some fake error—he gives you the real deal. The **built-in auth routes** respond with **RFC 7807 / RFC 9457 problem details**: JSON with `type`, `title`, `status`, and optional `detail`, plus extensions where it matters (e.g. session `key`, `reason`). **Content-Type** is `application/problem+json`. Every `type` URI in the response links to real documentation so you know what went wrong. See [docs/errors.md](docs/errors.md) for the full list and when each type is returned. Don't let them make it look fake.

| type URI                                                         | Meaning                                                      |
| ---------------------------------------------------------------- | ------------------------------------------------------------ |
| [docs/errors.md#config](docs/errors.md#config)                   | Configuration error                                          |
| [docs/errors.md#auth](docs/errors.md#auth)                       | Auth / token / ID token error                                |
| [docs/errors.md#challenge](docs/errors.md#challenge)             | PKCE or state generation error                               |
| [docs/errors.md#session](docs/errors.md#session)                 | Session get/set or type error (includes `key`, `reason`)     |
| [docs/errors.md#invalid_state](docs/errors.md#invalid_state)     | Invalid OAuth state payload                                  |
| [docs/errors.md#invalid_request](docs/errors.md#invalid_request) | Invalid callback request (e.g. missing code, nonce mismatch) |
| `about:blank`                                                    | Other or unknown error                                       |

Don't let them make it look fake. Handle your errors.

## Development and the Makefile (You Gotta Be Right Next to Me)

| Target                    | What it does                                                                                                                                                                                                   |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `help`                    | Default. Lists the real targets—no fake menus.                                                                                                                                                                 |
| `build`                   | Builds `bin/oauth-server`, `bin/app`, `bin/simulate`.                                                                                                                                                          |
| `test`                    | Runs `go test ./...`.                                                                                                                                                                                          |
| `generate-error-examples` | Runs `scripts/gen-error-examples.sh`: starts app and oauth-server, curls `__error_examples__/*`, writes `docs/error-examples/*.json` and rewrites the "Generated example responses" block in `docs/errors.md`. |
| `verify-docs`             | `git diff --exit-code docs/` — fails if docs are dirty so CI keeps decals real.                                                                                                                                |
| `ci`                      | `build`, `test`, `generate-error-examples`, `verify-docs`.                                                                                                                                                     |
| `install-playwright`      | Install Playwright browsers for `simulate`. You gotta be right next to the browser.                                                                                                                            |
| `pkce-sim`                | Depends on `build`; runs the PKCE simulation script.                                                                                                                                                           |

### About the example errors in docs

**docs/errors.md** lists every problem-detail type (config, auth, challenge, session, invalid_state, invalid_request, about:blank), when each is returned, and the **Generated example responses** section. **docs/error-examples/\*.json** are live JSON samples for each type. They're generated—not hand-written. Run `make generate-error-examples` and the script hits the app's `__error_examples__` routes, writes those JSON files, then rewrites the markdown code blocks in `docs/errors.md` from them. The Crooner don't leave you with fake examples; the docs stay real. CI runs `generate-error-examples` and `verify-docs`, so if you change code that affects error responses and forget to regenerate, the build fails. Don't let them make it look fake.

## Testing (You Gotta Be Right Next to Me)

Using Crooner in your app does **not** pull in Playwright—no fake passengers, baby. The main module has zero browser deps.

The PKCE simulation lives in the `simulate/` submodule. That module has Playwright as a dependency and the install CLI as a **tool**, so the version is pinned and you're not chasing `@latest` like some guy in a hot dog suit. To run the simulation from the repo root:

```bash
cd simulate && go run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps
cd .. && ./scripts/run-pkce-sim.sh
```

The script builds the app and mock OAuth server from the root module and the `simulate` binary from `simulate/`; starts the servers; and drives the browser through the happy path and security checks. If you skip the Playwright install, the simulation will fail—you gotta be right next to the browser for it to look real.

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

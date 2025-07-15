# crooner

<!--toc:start-->

- [crooner](#crooner)
  - [About](#about)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Configurable Content Security Policy (CSP)](#configurable-content-security-policy-csp)
    - [Usage](#usage)
    - [Why make CSP configurable?](#why-make-csp-configurable)
  - [Using Crooner with SCS (alexedwards/scs/v2)](#using-crooner-with-scs-alexedwardsscsv2)
  - [Todo](#todo)
  <!--toc:end-->

Crooner is a golang library for authenticating with an Azure app registration

![image](https://github.com/catgoose/screenshots/blob/fb17ed7cd8e989691447b0e7a755d93a677abbfd/crooner/crooner.png)

Ever want to authenticate with Azure in your Go project but MSAL has no
examples for a hosted HTTP service: <https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/468>

## About

Crooner is a Go library designed to simplify Azure authentication for Go-based
HTTP servers. It's built to address a specific use case of integrating Azure's
not intended to be a fully general-purpose OIDC authorization solution but focuses
on the specific needs of Azure app registrations.

If you're using a different framework or want to implement a more general solution
with the standard Go http library, PRs are welcome!

## Installation

```bash
go get github.com/catgoose/crooner@v1.0.0
```

## Usage

```go
import (
 "context"
 "log"
 "net/http"
 "os"

 "github.com/catgoose/crooner"
 "github.com/gorilla/sessions"
 "github.com/labstack/echo"
 "github.com/labstack/echo/middleware"
)

func getAzureConfig() *crooner.AuthConfigParams {
 return &crooner.AuthConfigParams{
  TenantID:          os.Getenv("AZURE_TENANT_ID"),
  ClientID:          os.Getenv("AZURE_CLIENT_ID"),
  ClientSecret:      os.Getenv("AZURE_CLIENT_SECRET"),
  RedirectURL:       os.Getenv("AZURE_REDIRECT_URL"),
  LogoutURLRedirect: os.Getenv("AZURE_LOGOUT_REDIRECT_URL"),
  LoginURLRedirect:  os.Getenv("AZURE_LOGIN_REDIRECT_URL"),
  AuthRoutes: &crooner.AuthRoutes{
   Login:    "/login",
   Logout:   "/logout",
   Callback: "/callback",
   // optional, routes exempt from auth middleware
   AuthExempt: []string{"/profile", "/about"}
  },
  // optional, additional scopes to request
  AdditionalScopes: []string{"User"},
  CookieName: "crooner-auth-key" // defaults to "crooner-auth"
 },
 // Map of session values to claims to store in session.
 // Use c.get("value") to retrieve claim
 SessionValueClaims: []map[string]string{
  {"azureId": "oid"},
 },
}

func main() {
 e := echo.New()

 e.Use(middleware.Logger())
 e.Use(middleware.Recover())

 // Initialize Crooner authentication
 params := getAzureConfig()

 secret := os.Getenv("SESSION_SECRET")
 store := sessions.NewCookieStore([]byte(secret))
 // CroonerConfig.SessionStore must be set
 params.CroonerConfig.SessionStore = store
 e.Use(session.Middleware(store))

 ctx := context.Background()
 err := crooner.NewAuthConfig(ctx, e, params)
 if err != nil {
  log.Fatalf("Failed to initialize Crooner: %v", err)
 }

 // Read azureId from session
 sess, err := session.Get("crooner-auth-key", c)
 if err != nil {
     return HandleError(c, http.StatusInternalServerError, "failed to retrieve session", err)
 }
 azureId, ok := sess.Values["azureId"].(string)
 if !ok || azureId == "" {
     return HandleError(c, http.StatusUnauthorized, "user not authenticated", nil)
 }
}
```

Note: Remember in Azure app registration to enable `ID tokens` to be issued

## Configurable Content Security Policy (CSP)

Crooner now supports configurable Content Security Policy (CSP) headers via the `SecurityHeadersConfig` struct. This allows you to control how strict or permissive your CSP is, depending on your application's needs.

### Usage

When initializing your authentication configuration, you can set the CSP like this:

```go
import (
    // ...
    "github.com/labstack/echo/v4"
)

params := &crooner.AuthConfigParams{
    // ... other config ...
    SecurityHeaders: &crooner.SecurityHeadersConfig{
        // Example: allow inline scripts/styles and data URLs for images
        ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
    },
}

// If not set, the default is strict: "default-src 'self'"
```

### Why make CSP configurable?

- **Strict CSP** (`default-src 'self'`): Best for security, but blocks inline scripts/styles and data URLs. Use this in production if possible.
- **Relaxed CSP** (e.g., allowing `'unsafe-inline'` or `data:`): Needed if your frontend or libraries (like htmx) require inline scripts/styles or data images.

**Note:** Adjust your CSP according to your application's security and functionality requirements.

## Using Crooner with SCS (alexedwards/scs/v2)

Crooner supports pluggable session backends via the `SessionManager` interface. To use SCS for session management:

1. Install SCS:

```bash
go get github.com/alexedwards/scs/v2
```

1. Set up SCS in your app and pass it to Crooner:

```go
import (
 "github.com/alexedwards/scs/v2"
 crooner "github.com/catgoose/crooner"
 "github.com/labstack/echo/v4"
)

func main() {
 e := echo.New()
 // ... other middleware ...

 // Set up SCS session manager
 scsMgr := scs.New()
 scsMgr.Cookie.Name = "crooner-auth-sitename"
 scsMgr.Cookie.HttpOnly = true
 scsMgr.Cookie.Secure = true
 scsMgr.Cookie.SameSite = http.SameSiteLaxMode
 scsMgr.Cookie.Persist = true
 scsMgr.Lifetime = 24 * time.Hour
 e.Use(echo.WrapMiddleware(scsMgr.LoadAndSave))

 // Set up Crooner config
 params := &crooner.AuthConfigParams{
  // ... other config ...
  SessionMgr: &crooner.SCSManager{Session: scsMgr},
 }

 // Initialize Crooner authentication
 ctx := context.Background()
 err := crooner.NewAuthConfig(ctx, e, params)
 if err != nil {
  log.Fatalf("Failed to initialize Crooner: %v", err)
 }

 // ... your routes ...
}
```

**Note:**

- All session operations will use SCS via the `SessionManager` interface.
- You can implement your own session backend by implementing the `SessionManager` interface if needed.

## Todo

- [ ] Create interface for saving session value to allow for other stores to
      store more information other than `azureId`

# crooner

<!--toc:start-->

- [crooner](#crooner)
  - [About](#about)
  - [Installation](#installation)
  - [Usage](#usage)
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
   AuthExempt: []string{"/profile", "/about"} // optional, routes exempt from auth middleware
  },
  AdditionalScopes: []string{"User"}, // optional, additional scopes to request
 }
}

func main() {
 e := echo.New()

 e.Use(middleware.Logger())
 e.Use(middleware.Recover())

 secret := os.Getenv("SESSION_SECRET")
 store := sessions.NewCookieStore([]byte(secret))
 e.Use(session.Middleware(store))

 // Initialize Crooner authentication
 params := getAzureConfig()
 err := crooner.NewAuthConfig(e, context.Background(), params)
 if err != nil {
  log.Fatalf("Failed to initialize Crooner: %v", err)
 }
}
```

Note: Remember in Azure app registration to enable `ID tokens` to be issued

## Todo

- [ ] Create session methods for retrieving user profile

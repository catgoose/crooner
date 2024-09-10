# crooner

<!--toc:start-->

- [crooner](#crooner)
  - [About](#about)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Todo](#todo)
  <!--toc:end-->

Crooner is a golang library for authenticating with an Azure app registration

![image](https://github.com/catgoose/crooner/blob/41cd66a9a377448bb5fe7fdae11ec944de53835f/crooner.png)

Ever want to authenticate with Azure in your Go project but MSAL has no
examples for a hosted HTTP service: <https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/468>

![image](https://github.com/catgoose/crooner/blob/41cd66a9a377448bb5fe7fdae11ec944de53835f/be_here.png)

![image](https://github.com/catgoose/crooner/blob/4be4936dedb862dfe0754cb61f26795ca97b3c7d/it_sucks.png)

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
  SessionSecret:     os.Getenv("SESSION_SECRET"),
  AuthRoutes: &crooner.AuthRoutes{
   Login:    "/login",
   Logout:   "/logout",
   Callback: "/callback",
   Redirect: "/login",
   AuthExempt: []string{"/profile", "/about"} // optional, routes exempt from auth middleware
  },
  AdditionalScopes: []string{"User"}, // optional, additional scopes to request
 }
}

func main() {
 e := echo.New()

 e.Use(middleware.Logger())
 e.Use(middleware.Recover())

 // Initialize Crooner authentication
 params := getAzureConfig()
 err := crooner.NewAuthConfig(e, context.Background(), params)
 if err != nil {
  log.Fatalf("Failed to initialize Crooner: %v", err)
 }
}
```

In Azure app registration remember to enable `ID tokens` to be issued

![image](https://github.com/catgoose/crooner/blob/4be4936dedb862dfe0754cb61f26795ca97b3c7d/sloppy.png)

## Todo

- [ ] Create session methods for retrieving user profile

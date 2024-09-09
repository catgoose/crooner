# crooner

Crooner is a golang module for authenticating with an Azure app registration

![image](https://github.com/catgoose/crooner/blob/41cd66a9a377448bb5fe7fdae11ec944de53835f/crooner.png)

Ever want to authenticate with Azure in your Go project but MSAL has no
examples for a hosted HTTP service: <https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/468>

![image](https://github.com/catgoose/crooner/blob/41cd66a9a377448bb5fe7fdae11ec944de53835f/be_here.png)

![image](https://github.com/catgoose/crooner/blob/4be4936dedb862dfe0754cb61f26795ca97b3c7d/it_sucks.png)

## Usage with echo

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

var store = sessions.NewCookieStore([]byte(internals.os.Getenv("SESSION_SECRET")))

func authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
 return func(c echo.Context) error {
  if c.Path() == "/login" || c.Path() == "/callback" || c.Path() == "/logout" {
   return next(c)
  }
  session, _ := store.Get(c.Request(), "session-name")
  userEmail, ok := session.Values["user"].(string)
  if !ok || userEmail == "" {
   return c.Redirect(http.StatusFound, "/login")
  }
  return next(c)
 }
}

func getAzureConfig() *crooner.AuthConfigParams {
 config := &crooner.AuthConfigParams{
  TenantID:          os.Getenv("AZURE_TENANT_ID"),
  ClientID:          os.Getenv("AZURE_CLIENT_ID"),
  ClientSecret:      os.Getenv("AZURE_CLIENT_SECRET"),
  RedirectURL:       os.Getenv("AZURE_REDIRECT_URL"),
  LogoutURLRedirect: os.Getenv("AZURE_LOGOUT_REDIRECT_URL"),
  LoginURLRedirect:  os.Getenv("AZURE_LOGIN_REDIRECT_URL"),
 }
 return config
}

func main() {
 params := getAzureConfig()
 authConfig, err := crooner.NewAuthConfig(context.Background(), params)
 if err != nil {
  log.Fatalf("Failed to initialize crooner: %v", err)
 }

 authHandler := crooner.NewAuthHandlerConfig(authConfig, store)
 e := echo.New()

 e.Use(middleware.Logger())
 e.Use(middleware.Recover())
 e.Use(authMiddleware)

 e.GET("/login", echo.WrapHandler(http.HandlerFunc(authHandler.LoginHandler())))
 e.GET("/callback", echo.WrapHandler(http.HandlerFunc(authHandler.CallbackHandler())))
 e.GET("/logout", echo.WrapHandler(http.HandlerFunc(authHandler.LogoutHandler())))
}
```

In Azure app registration remember to enable `ID tokens` to be issued

Crooner uses [gorilla](https://gorilla.github.io/) for session state management.
Open a PR if you want to a different session management

If you know what I mean

![image](https://github.com/catgoose/crooner/blob/4be4936dedb862dfe0754cb61f26795ca97b3c7d/sloppy.png)

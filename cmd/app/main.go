package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	crooner "github.com/catgoose/crooner"
	"github.com/labstack/echo/v4"
)

func main() {
	port := flag.String("port", "8080", "listen port")
	issuerURL := flag.String("issuer", "", "OIDC issuer URL (mock server, e.g. http://localhost:9998)")
	redirectURL := flag.String("redirect", "", "OAuth redirect URL (e.g. http://localhost:8080/callback)")
	sessionSecret := flag.String("session-secret", "test-secret-change-in-production", "session secret")
	flag.Parse()

	if *issuerURL == "" {
		*issuerURL = os.Getenv("ISSUER_URL")
	}
	if *issuerURL == "" {
		*issuerURL = "http://localhost:9998"
	}
	if *redirectURL == "" {
		*redirectURL = os.Getenv("REDIRECT_URL")
	}
	if *redirectURL == "" {
		*redirectURL = "http://localhost:" + *port + "/callback"
	}
	baseURL := "http://localhost:" + *port

	sessionMgr, scsMgr, err := crooner.NewSCSManager(
		crooner.WithPersistentCookieName(*sessionSecret, "crooner-app"),
		crooner.WithLifetime(12*time.Hour),
		crooner.WithCookieSecure(false),
	)
	if err != nil {
		log.Fatalf("session manager: %v", err)
	}

	e := echo.New()
	e.Use(echo.WrapMiddleware(scsMgr.LoadAndSave))

	routes := &crooner.AuthRoutes{
		Login:    "/login",
		Logout:   "/logout",
		Callback: "/callback",
	}

	params := &crooner.AuthConfigParams{
		SessionMgr:        sessionMgr,
		AuthRoutes:        routes,
		IssuerURL:         *issuerURL,
		ClientID:          "crooner-test-client",
		RedirectURL:       *redirectURL,
		LoginURLRedirect:  baseURL + "/",
		LogoutURLRedirect: baseURL + "/",
	}
	if os.Getenv("GEN_ERROR_EXAMPLES") == "1" {
		params.ErrorConfig = &crooner.ErrorConfig{ShowDetails: true}
	}
	if err := crooner.NewAuthConfig(context.Background(), e, params); err != nil {
		log.Fatalf("auth config: %v", err)
	}

	e.GET("/", func(c echo.Context) error {
		user, _ := crooner.GetString(sessionMgr, c, crooner.SessionKeyUser)
		if user == "" {
			user = "anonymous"
		}
		return c.String(200, "OK\nuser: "+user)
	})

	addr := ":" + *port
	log.Printf("app listening on %s", addr)
	log.Fatal(e.Start(addr))
}

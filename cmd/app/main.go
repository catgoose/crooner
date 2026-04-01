package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	crooner "github.com/catgoose/crooner"
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

	mux := http.NewServeMux()

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
		ClientSecret:      "mock",
		RedirectURL:       *redirectURL,
		LoginURLRedirect:  baseURL + "/",
		LogoutURLRedirect: baseURL + "/",
	}
	if os.Getenv("GEN_ERROR_EXAMPLES") == "1" {
		params.ErrorConfig = &crooner.ErrorConfig{ShowDetails: true}
		params.AuthRoutes.AuthExempt = append(params.AuthRoutes.AuthExempt, "/__error_examples__/")
	}
	authHandler, err := crooner.NewAuthConfig(context.Background(), mux, params)
	if err != nil {
		log.Fatalf("auth config: %v", err)
	}
	authHandler.SetupErrorExampleRoutes(mux)

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		user, _ := crooner.GetString(sessionMgr, r, crooner.SessionKeyUser)
		if user == "" {
			user = "anonymous"
		}
		w.WriteHeader(200)
		w.Write([]byte("OK\nuser: " + user))
	})

	// Build middleware chain: session loading -> auth middleware -> mux
	var handler http.Handler = mux
	handler = authHandler.Middleware()(handler)
	handler = scsMgr.LoadAndSave(handler)

	addr := ":" + *port
	log.Printf("app listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var (
	port     = flag.String("port", "9998", "listen port")
	issuer   = flag.String("issuer", "", "issuer URL (default http://localhost:<port>)")
	testUser = "test-user@example.com"
)

type authGrant struct {
	Created       time.Time
	RedirectURI   string
	State         string
	CodeChallenge string
	Nonce         string
	ClientID      string
}

var (
	grants   = make(map[string]*authGrant)
	grantsMu sync.RWMutex
)

const codeTTL = 5 * time.Minute

func main() {
	flag.Parse()
	addr := ":" + *port
	if *issuer == "" {
		*issuer = "http://localhost" + addr
	}
	*issuer = strings.TrimSuffix(*issuer, "/")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "mock-kid", Algorithm: string(jose.RS256), Use: "sig"}
	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", discoveryHandler(addr))
	mux.HandleFunc("/authorize", authorizeHandler())
	mux.HandleFunc("/token", tokenHandler(key, jwks))
	mux.HandleFunc("/jwks", jwksHandler(jwks))

	log.Printf("mock OIDC server listening on %s issuer=%s", addr, *issuer)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func discoveryHandler(addr string) http.HandlerFunc {
	base := *issuer
	if base == "" {
		base = "http://localhost" + addr
	}
	doc := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"jwks_uri":                              base + "/jwks",
		"response_types_supported":              []string{"code"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}
}

func authorizeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		codeChallenge := q.Get("code_challenge")
		nonce := q.Get("nonce")
		clientID := q.Get("client_id")
		if redirectURI == "" || state == "" || codeChallenge == "" || clientID == "" {
			http.Error(w, "missing required query parameter", http.StatusBadRequest)
			return
		}
		code := make([]byte, 32)
		if _, err := rand.Read(code); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		codeStr := base64.RawURLEncoding.EncodeToString(code)

		grantsMu.Lock()
		grants[codeStr] = &authGrant{
			RedirectURI:   redirectURI,
			State:         state,
			CodeChallenge: codeChallenge,
			Nonce:         nonce,
			ClientID:      clientID,
			Created:       time.Now(),
		}
		grantsMu.Unlock()

		redir, _ := url.Parse(redirectURI)
		redir.RawQuery = url.Values{"code": {codeStr}, "state": {state}}.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
	}
}

func tokenHandler(privateKey *rsa.PrivateKey, jwks *jose.JSONWebKeySet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		codeVerifier := r.FormValue("code_verifier")
		redirectURI := r.FormValue("redirect_uri")
		clientID := r.FormValue("client_id")
		if code == "" || codeVerifier == "" || redirectURI == "" || clientID == "" {
			writeTokenError(w, "invalid_request", "missing parameter", http.StatusBadRequest)
			return
		}

		grantsMu.Lock()
		g, ok := grants[code]
		if !ok {
			grantsMu.Unlock()
			writeTokenError(w, "invalid_grant", "code not found or already used", http.StatusBadRequest)
			return
		}
		if time.Since(g.Created) > codeTTL {
			delete(grants, code)
			grantsMu.Unlock()
			writeTokenError(w, "invalid_grant", "code expired", http.StatusBadRequest)
			return
		}
		hash := sha256.Sum256([]byte(codeVerifier))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])
		if challenge != g.CodeChallenge {
			grantsMu.Unlock()
			writeTokenError(w, "invalid_grant", "code_verifier does not match challenge", http.StatusBadRequest)
			return
		}
		if g.RedirectURI != redirectURI || g.ClientID != clientID {
			delete(grants, code)
			grantsMu.Unlock()
			writeTokenError(w, "invalid_grant", "redirect_uri or client_id mismatch", http.StatusBadRequest)
			return
		}
		delete(grants, code)
		grantsMu.Unlock()

		now := time.Now()
		idToken, err := signIDToken(privateKey, *issuer, clientID, g.Nonce, testUser, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	}
}

func writeTokenError(w http.ResponseWriter, code, desc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func signIDToken(key *rsa.PrivateKey, iss, aud, nonce, sub string, now time.Time) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{jose.HeaderKey("kid"): "mock-kid"}})
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"iss":                iss,
		"sub":                sub,
		"aud":                aud,
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
		"nonce":              nonce,
		"email":              sub,
		"preferred_username": sub,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payloadBytes)
	if err != nil {
		return "", err
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		return "", err
	}
	return compact, nil
}

func jwksHandler(jwks *jose.JSONWebKeySet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}
}

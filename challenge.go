package crooner

import (
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/exp/rand"
)

// GenerateCodeChallenge generates a SHA256 code challenge from the verifier
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateCodeVerifier generates a random PKCE code verifier
func GenerateCodeVerifier() (string, error) {
	verifier := make([]byte, 64)
	if _, err := rand.Read(verifier); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(verifier), nil
}

// GenerateState generates a cryptographically secure random state parameter for OAuth2
func GenerateState() (string, error) {
	state := make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(state), nil
}

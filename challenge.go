package crooner

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// ChallengeError represents an error during PKCE challenge or state generation.
type ChallengeError struct {
	Err error
	Op  string
}

func (e *ChallengeError) Error() string {
	return fmt.Sprintf("challenge error during %s: %v", e.Op, e.Err)
}

func (e *ChallengeError) Unwrap() error { return e.Err }

// IsChallengeError checks if an error is a ChallengeError
func IsChallengeError(err error) bool {
	var challengeErr *ChallengeError
	return errors.As(err, &challengeErr)
}

// AsChallengeError attempts to convert an error to ChallengeError
func AsChallengeError(err error) (*ChallengeError, bool) {
	var challengeErr *ChallengeError
	if errors.As(err, &challengeErr) {
		return challengeErr, true
	}
	return nil, false
}

// GenerateCodeChallenge generates a SHA256 code challenge from the verifier
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateCodeVerifier generates a random PKCE code verifier
func GenerateCodeVerifier() (string, error) {
	verifier := make([]byte, 64)
	if _, err := rand.Read(verifier); err != nil {
		return "", &ChallengeError{Op: "GenerateCodeVerifier", Err: err}
	}
	return base64.RawURLEncoding.EncodeToString(verifier), nil
}

// GenerateState generates a cryptographically secure random state parameter for OAuth2
func GenerateState() (string, error) {
	state := make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		return "", &ChallengeError{Op: "GenerateState", Err: err}
	}
	return base64.RawURLEncoding.EncodeToString(state), nil
}

package crooner

import (
	"encoding/base64"
	"regexp"
	"testing"
)

func TestGenerateCodeVerifier_LengthAndFormat(t *testing.T) {
	v, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("code verifier not valid base64url: %v", err)
	}
	if len(decoded) != 64 {
		t.Errorf("code verifier decoded length = %d, want 64", len(decoded))
	}
}

func TestGenerateCodeChallenge_Deterministic(t *testing.T) {
	verifier := "test-verifier-string"
	a := GenerateCodeChallenge(verifier)
	b := GenerateCodeChallenge(verifier)
	if a != b {
		t.Errorf("GenerateCodeChallenge not deterministic: %q != %q", a, b)
	}
	matched, _ := regexp.MatchString(`^[A-Za-z0-9_-]+$`, a)
	if !matched {
		t.Errorf("code challenge not base64url-like: %q", a)
	}
}

func TestGenerateState_LengthAndFormat(t *testing.T) {
	s, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("state not valid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("state decoded length = %d, want 32", len(decoded))
	}
}

func TestGenerateState_IsChallengeError(t *testing.T) {
	s, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	if s == "" {
		t.Error("GenerateState returned empty string")
	}
}

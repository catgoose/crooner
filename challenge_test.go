package crooner

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
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

func TestChallengeError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("inner")
	ce := &ChallengeError{Op: "TestOp", Err: inner}
	if ce.Error() == "" {
		t.Error("ChallengeError.Error() empty")
	}
	if !strings.Contains(ce.Error(), "TestOp") || !strings.Contains(ce.Error(), "inner") {
		t.Errorf("ChallengeError.Error() = %q", ce.Error())
	}
	if ce.Unwrap() != inner {
		t.Error("ChallengeError.Unwrap() != inner")
	}
	ceNoErr := &ChallengeError{Op: "Op", Err: nil}
	if ceNoErr.Error() == "" {
		t.Error("ChallengeError with nil Err: Error() empty")
	}
	if ceNoErr.Unwrap() != nil {
		t.Error("ChallengeError with nil Err: Unwrap() != nil")
	}
}

func TestChallengeError_IsChallengeError_AsChallengeError(t *testing.T) {
	ce := &ChallengeError{Op: "Op", Err: nil}
	if !IsChallengeError(ce) {
		t.Error("IsChallengeError(ChallengeError) = false")
	}
	got, ok := AsChallengeError(ce)
	if !ok || got != ce {
		t.Errorf("AsChallengeError = %v, %v; want ce, true", got, ok)
	}
	if IsChallengeError(nil) {
		t.Error("IsChallengeError(nil) = true")
	}
	_, ok = AsChallengeError(nil)
	if ok {
		t.Error("AsChallengeError(nil) = true")
	}
	wrapped := errors.Join(ce, errors.New("other"))
	if !IsChallengeError(wrapped) {
		t.Error("IsChallengeError(wrapped ChallengeError) = false")
	}
	got, ok = AsChallengeError(wrapped)
	if !ok || got != ce {
		t.Errorf("AsChallengeError(wrapped) = %v, %v", got, ok)
	}
}

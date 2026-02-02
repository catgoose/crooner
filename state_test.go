package crooner

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestEncodeStatePayload_DecodeStatePayload_RoundTrip(t *testing.T) {
	csrfState := "abc123"
	originalPath := "/dashboard?id=42"
	encoded := EncodeStatePayload(csrfState, originalPath)
	decoded, err := DecodeStatePayload(encoded)
	if err != nil {
		t.Fatalf("DecodeStatePayload: %v", err)
	}
	if decoded != originalPath {
		t.Errorf("decoded path = %q, want %q", decoded, originalPath)
	}
}

func TestEncodeStatePayload_EmptyPathDefaultsToSlash(t *testing.T) {
	encoded := EncodeStatePayload("state", "")
	decoded, err := DecodeStatePayload(encoded)
	if err != nil {
		t.Fatalf("DecodeStatePayload: %v", err)
	}
	if decoded != "/" {
		t.Errorf("decoded path = %q, want \"/\"", decoded)
	}
}

func TestDecodeStatePayload_InvalidBase64(t *testing.T) {
	_, err := DecodeStatePayload("!!!not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !errors.Is(err, ErrInvalidStateFormat) {
		t.Errorf("errors.Is(err, ErrInvalidStateFormat) = false, got err: %v", err)
	}
}

func TestDecodeStatePayload_MalformedPayload_NoPipe(t *testing.T) {
	raw := "onlyonepart"
	_, err := DecodeStatePayload(base64.StdEncoding.EncodeToString([]byte(raw)))
	if err == nil {
		t.Fatal("expected error for malformed payload")
	}
	if !errors.Is(err, ErrInvalidStateData) {
		t.Errorf("errors.Is(err, ErrInvalidStateData) = false, got err: %v", err)
	}
}

func TestDecodeStatePayload_MalformedPayload_Empty(t *testing.T) {
	_, err := DecodeStatePayload(base64.StdEncoding.EncodeToString([]byte("")))
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
	if !errors.Is(err, ErrInvalidStateData) {
		t.Errorf("errors.Is(err, ErrInvalidStateData) = false, got err: %v", err)
	}
}

func TestDecodeStatePayload_EmptySecondPart_DefaultsToSlash(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("csrf|"))
	decoded, err := DecodeStatePayload(encoded)
	if err != nil {
		t.Fatalf("DecodeStatePayload: %v", err)
	}
	if decoded != "/" {
		t.Errorf("decoded path = %q, want \"/\"", decoded)
	}
}

package crooner

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateErrorExamples(t *testing.T) {
	if os.Getenv("CROONER_GEN_ERROR_EXAMPLES") != "1" {
		t.Skip("set CROONER_GEN_ERROR_EXAMPLES=1 to generate docs/error-examples/*.json")
	}
	outDir := "docs/error-examples"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll %s: %v", outDir, err)
	}
	onlySlugs := make(map[string]bool)
	if s := os.Getenv("CROONER_GEN_ERROR_SLUGS"); s != "" {
		for _, slug := range strings.Split(s, ",") {
			onlySlugs[strings.TrimSpace(slug)] = true
		}
	}

	a := minimalAuthHandlerConfig(newMapSessionManager())
	a.ErrorConfig = &ErrorConfig{ShowDetails: true}

	type case_ struct {
		slug   string
		status int
		msg    string
		err    error
	}
	cases := []case_{
		{"config", 400, "invalid redirect", &ConfigError{Field: "RedirectURL", Reason: "invalid URL", Err: nil}},
		{"auth", 500, "token failed", &AuthError{Op: "VerifyIDToken", Reason: "bad token", Err: nil}},
		{"challenge", 500, "Failed to generate state", &ChallengeError{Op: "GenerateState", Err: nil}},
		{"session", 400, "Code verifier not found", &SessionError{Key: "code_verifier", Reason: ReasonNotFound}},
		{"invalid_state", 400, "Invalid state format", ErrInvalidStateFormat},
		{"invalid_request", 400, "Nonce mismatch", ErrNonceMismatch},
		{"about_blank", 400, "unknown", errors.New("unknown")},
	}

	for _, c := range cases {
		if len(onlySlugs) > 0 && !onlySlugs[c.slug] {
			continue
		}
		req := httptest.NewRequest(http.MethodGet, "/callback", nil)
		req.Host = "example.com"
		rec := httptest.NewRecorder()
		a.handleError(rec, req, c.status, c.msg, c.err)
		var pd ProblemDetails
		if err := json.NewDecoder(rec.Body).Decode(&pd); err != nil {
			t.Fatalf("%s: decode: %v", c.slug, err)
		}
		out, err := os.Create(filepath.Join(outDir, c.slug+".json"))
		if err != nil {
			t.Fatalf("%s: create: %v", c.slug, err)
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(pd); err != nil {
			out.Close()
			t.Fatalf("%s: write: %v", c.slug, err)
		}
		out.Close()
	}
}

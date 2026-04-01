package crooner

import (
	"errors"
	"net/http"
	"os"
	"strings"
)

const errorExamplesPrefix = "/__error_examples__"

// SetupErrorExampleRoutes registers error-example routes on the given mux.
// These routes are only used by the gen-error-examples script for generating
// docs/error-examples/*.json fixtures. The routes are gated behind
// errorExampleRoutesEnabled() so they never appear in production.
func (a *AuthHandlerConfig) SetupErrorExampleRoutes(mux *http.ServeMux) {
	if !errorExampleRoutesEnabled() {
		return
	}
	mux.HandleFunc("GET "+errorExamplesPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		slug := strings.TrimPrefix(r.URL.Path, errorExamplesPrefix+"/")
		var status int
		var msg string
		var errVal error
		switch slug {
		case "config":
			status, msg, errVal = 400, "invalid redirect", &ConfigError{Field: "RedirectURL", Reason: "invalid URL"}
		case "auth":
			status, msg, errVal = 500, "token failed", &AuthError{Op: "VerifyIDToken", Reason: "bad token"}
		case "challenge":
			status, msg, errVal = 500, "Failed to generate state", &ChallengeError{Op: "GenerateState"}
		case "session":
			status, msg, errVal = 400, "Code verifier not found", &SessionError{Key: "code_verifier", Reason: ReasonNotFound}
		case "invalid_state":
			status, msg, errVal = 400, "Invalid state format", ErrInvalidStateFormat
		case "invalid_request":
			status, msg, errVal = 400, "Nonce mismatch", ErrNonceMismatch
		case "about_blank":
			status, msg, errVal = 400, "unknown", errors.New("unknown")
		default:
			http.NotFound(w, r)
			return
		}
		a.handleError(w, r, status, msg, errVal)
	})
}

func errorExampleRoutesEnabled() bool {
	return os.Getenv("GEN_ERROR_EXAMPLES") == "1" ||
		os.Getenv("CI") == "true" ||
		os.Getenv("GITHUB_ACTIONS") == "true"
}

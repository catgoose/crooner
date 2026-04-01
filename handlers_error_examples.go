package crooner

import (
	"errors"
	"net/http"
	"os"
	"strings"
)

const errorExamplesPrefix = "/__error_examples__"

func setupErrorExampleRoutes(mux *http.ServeMux, a *AuthHandlerConfig) {
	mux.HandleFunc("GET "+errorExamplesPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		slug := strings.TrimPrefix(r.URL.Path, errorExamplesPrefix+"/")
		var status int
		var msg string
		var errVal error
		switch slug {
		case "config":
			status, msg, errVal = 400, "invalid redirect", &ConfigError{Field: "RedirectURL", Reason: "invalid URL", Err: nil}
		case "auth":
			status, msg, errVal = 500, "token failed", &AuthError{Op: "VerifyIDToken", Reason: "bad token", Err: nil}
		case "challenge":
			status, msg, errVal = 500, "Failed to generate state", &ChallengeError{Op: "GenerateState", Err: nil}
		case "session":
			status, msg, errVal = 400, "Code verifier not found", &SessionError{Key: "code_verifier", Reason: ReasonNotFound}
		case "invalid_state":
			status, msg, errVal = 400, "Invalid state format", ErrInvalidStateFormat
		case "invalid_request":
			status, msg, errVal = 400, "Nonce mismatch", ErrNonceMismatch
		case "about_blank":
			status, msg, errVal = 400, "unknown", errors.New("unknown")
		default:
			w.WriteHeader(http.StatusNotFound)
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

package crooner

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

var unsafeMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

type csrfOpts struct {
	headerName    string
	formFieldName string
	exemptPaths   []string
}

// CSRFOption configures the CSRF middleware.
type CSRFOption func(*csrfOpts)

// CSRFHeaderName sets the request header name to read the token from (default "X-CSRF-Token").
func CSRFHeaderName(name string) CSRFOption {
	return func(o *csrfOpts) {
		o.headerName = name
	}
}

// CSRFFormFieldName sets the form field name for the token (default "csrf_token").
func CSRFFormFieldName(name string) CSRFOption {
	return func(o *csrfOpts) {
		o.formFieldName = name
	}
}

// CSRFExemptPaths sets path prefixes that skip CSRF validation (e.g. webhooks).
func CSRFExemptPaths(paths []string) CSRFOption {
	return func(o *csrfOpts) {
		o.exemptPaths = paths
	}
}

func isCSRFExemptPath(path string, exempt []string) bool {
	for _, p := range exempt {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// CSRF returns standard middleware that validates CSRF tokens on unsafe methods (POST, PUT, PATCH, DELETE)
// and sets the token on the response for safe methods when the session has a user.
func CSRF(sm SessionManager, opts ...CSRFOption) func(http.Handler) http.Handler {
	o := &csrfOpts{
		headerName:    "X-CSRF-Token",
		formFieldName: "csrf_token",
	}
	for _, opt := range opts {
		opt(o)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method := r.Method
			path := r.URL.Path
			if unsafeMethods[method] {
				if !isCSRFExemptPath(path, o.exemptPaths) {
					expected, err := GetString(sm, r, SessionKeyCSRFToken)
					if err != nil {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					received := r.Header.Get(o.headerName)
					if received == "" {
						received = r.FormValue(o.formFieldName)
					}
					if len(received) != len(expected) || subtle.ConstantTimeCompare([]byte(received), []byte(expected)) != 1 {
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
			} else {
				if _, err := GetString(sm, r, SessionKeyUser); err == nil {
					if token, err := GetOrCreateCSRFToken(sm, r); err == nil {
						w.Header().Set(o.headerName, token)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

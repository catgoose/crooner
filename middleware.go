package crooner

import (
	"net/http"
)

type securityHeaderSpec struct {
	getVal func(*SecurityHeadersConfig) string
	key    string
	def    string
}

var securityHeaderSpecs = []securityHeaderSpec{
	{key: "Content-Security-Policy", def: "default-src 'self'", getVal: func(h *SecurityHeadersConfig) string { return h.ContentSecurityPolicy }},
	{key: "X-Frame-Options", def: "DENY", getVal: func(h *SecurityHeadersConfig) string { return h.XFrameOptions }},
	{key: "X-Content-Type-Options", def: "nosniff", getVal: func(h *SecurityHeadersConfig) string { return h.XContentTypeOptions }},
	{key: "Referrer-Policy", def: "strict-origin-when-cross-origin", getVal: func(h *SecurityHeadersConfig) string { return h.ReferrerPolicy }},
	{key: "X-XSS-Protection", def: "1; mode=block", getVal: func(h *SecurityHeadersConfig) string { return h.XXSSProtection }},
}

// SecurityHeadersMiddleware returns standard middleware that applies SecurityHeadersConfig to responses.
// If cfg is nil, defaults are used for all headers.
func SecurityHeadersMiddleware(cfg *SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := cfg
			if h == nil {
				h = &SecurityHeadersConfig{}
			}
			for _, spec := range securityHeaderSpecs {
				val := spec.getVal(h)
				if val == "" {
					val = spec.def
				}
				w.Header().Set(spec.key, val)
			}
			if h.StrictTransportSecurity != "" && requestScheme(r) == "https" {
				w.Header().Set("Strict-Transport-Security", h.StrictTransportSecurity)
			}
			next.ServeHTTP(w, r)
		})
	}
}


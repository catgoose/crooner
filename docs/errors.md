# Problem detail types

Crooner’s built-in auth routes (login, callback, logout) return [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) / [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem details when an error occurs. Auth routes always use `Content-Type: application/problem+json`. For app-level session errors outside these auth routes, `SessionErrorResponse` in `session.go` returns a different JSON shape; auth handlers do not use it. The `type` field in the problem response is one of the URIs below; each links to this section so you can see when it is returned and what it means.

## config

Returned when configuration validation fails or the OIDC provider cannot be initialized (e.g. invalid or missing `NewAuthConfig` parameters, discovery fetch failure). Extensions: `field` (config field name), `reason` (e.g. missing required parameter, invalid URL). Indicates a setup or configuration error.

Example: `{"type":".../errors.md#config","title":"Configuration error","detail":"...","instance":"...","status":500,"field":"RedirectURL","reason":"invalid URL"}`

## auth

Returned when token exchange or ID token verification fails (e.g. `ExchangeToken` or `VerifyIDToken`). Extensions: `op` (operation name), `reason` (short reason string). Indicates an authentication or OIDC error.

Example: `{"type":".../errors.md#auth","title":"Authentication error","detail":"...","instance":"...","status":500,"op":"VerifyIDToken","reason":"failed to verify ID token"}`

## challenge

Returned when PKCE or state generation fails (e.g. `GenerateState`, `GenerateCodeVerifier`). Indicates a challenge generation error.

Example: `{"type":".../errors.md#challenge","title":"Challenge generation failed","detail":"Failed to generate state","instance":"...","status":500}`

## session

Returned when a session get/set fails or a session value has the wrong type (e.g. `GetString` for a missing key or non-string value). Extensions: `key` (session key involved), `reason` (one of `not found`, `invalid type`). Indicates a session operation error.

Example: `{"type":".../errors.md#session","title":"Session error","detail":"Code verifier not found","instance":"...","status":400,"key":"code_verifier","reason":"not found"}`

## invalid_state

Returned when the OAuth state payload is invalid (bad base64 or malformed payload). Indicates an invalid state decode error.

Example: `{"type":".../errors.md#invalid_state","title":"Invalid state","detail":"Invalid state format","instance":"...","status":400}`

## invalid_request

Returned when a callback request is invalid (e.g. authorization code not provided, nonce mismatch). Indicates a bad or missing request parameter that the client can correct.

Example: `{"type":".../errors.md#invalid_request","title":"Invalid request","detail":"Authorization code not provided","instance":"...","status":400}`

## other

Used for any other error (Crooner sends `type: "about:blank"` in that case). Indicates an unknown or uncategorized error.

Example: `{"type":"about:blank","title":"Authorization code not provided","detail":"Authorization code not provided","instance":"...","status":400}`

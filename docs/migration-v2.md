# Migration Guide: Crooner v1 → v2 (The Real Deal, No Fake Upgrades)

> You gotta give, baby. The Crooner's going provider-agnostic. No more Azure-only ride—now
> anybody with an OIDC-compliant provider can hop in the car. But that means a few things
> changed, and if you don't update your code, it's gonna look fake. Don't let them make it
> look fake.

## What Changed and Why

Crooner v1 had Azure AD baked into its bones—hardcoded `login.microsoftonline.com` URLs,
UUID validation on `ClientID` and `TenantID`, mandatory `ClientSecret`. That's fine if
you're only driving with Microsoft, but some people want to ride with Google, Okta, Auth0,
Keycloak—you name it. So we ripped out the Azure-specific code and made `IssuerURL` the
one true path. One config shape, any provider. The hat and the cigar.

## Breaking Changes

| What                    | v1                                                     | v2                                                       |
| ----------------------- | ------------------------------------------------------ | -------------------------------------------------------- |
| `TenantID`              | Required (or `IssuerURL` as alternative)               | **Removed** from `AuthConfigParams` and `AuthConfig`     |
| `IssuerURL`             | Optional (alternative to `TenantID`)                   | **Required**                                             |
| `ClientID` validation   | UUID format required (Azure)                           | Any non-empty string                                     |
| `ClientSecret`          | Required                                               | **Optional** (public clients don't need it)              |
| Azure fallback endpoint | `login.microsoftonline.com/{tenant}/v2.0` auto-built   | **Removed** — you provide the full `IssuerURL`           |
| Azure logout fallback   | Hardcoded Azure logout URL when `TenantID` was set     | **Removed** — uses OIDC `end_session_endpoint` discovery |
| `microsoft` import      | `golang.org/x/oauth2/microsoft` used internally        | **Removed**                                              |

## Step-by-Step Migration

### 1. Replace `TenantID` with `IssuerURL`

**Before (v1):**

```go
params := &crooner.AuthConfigParams{
    TenantID:     os.Getenv("AZURE_TENANT_ID"),
    ClientID:     os.Getenv("AZURE_CLIENT_ID"),
    ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
    // ...
}
```

**After (v2):**

```go
params := &crooner.AuthConfigParams{
    IssuerURL:    os.Getenv("OIDC_ISSUER_URL"),    // e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
    ClientID:     os.Getenv("OIDC_CLIENT_ID"),
    ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"), // optional for public clients
    // ...
}
```

If you were using Azure AD with a tenant ID like `00000000-0000-0000-0000-000000000000`,
your `IssuerURL` is:

```
https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0
```

That's it. Same provider, just spelled out. No more magic. The Crooner don't guess where
you're going—you tell him.

### 2. Remove `TenantID` from Your Config

Delete any references to `TenantID` in your `AuthConfigParams`. The field no longer exists.
The compiler will tell you if you missed one—don't let it look fake.

### 3. Update Environment Variables

If you were using `AZURE_*` env vars, rename them. Not required, but keeps things clean now
that Crooner rides with anybody:

| Old                        | New (suggested)             |
| -------------------------- | --------------------------- |
| `AZURE_TENANT_ID`          | _(removed — bake into URL)_ |
| `AZURE_CLIENT_ID`          | `OIDC_CLIENT_ID`            |
| `AZURE_CLIENT_SECRET`      | `OIDC_CLIENT_SECRET`        |
| `AZURE_REDIRECT_URL`       | `OIDC_REDIRECT_URL`         |
| `AZURE_LOGOUT_REDIRECT_URL`| `OIDC_LOGOUT_REDIRECT_URL`  |
| `AZURE_LOGIN_REDIRECT_URL` | `OIDC_LOGIN_REDIRECT_URL`   |
| _(new)_                    | `OIDC_ISSUER_URL`           |

### 4. Update CSP Headers (If Referencing Azure Domains)

If your `ContentSecurityPolicy` included `https://login.microsoftonline.com`, update it for
your provider's domains:

**Before:**

```go
ContentSecurityPolicy: "img-src 'self' data: https://login.microsoftonline.com;"
```

**After:**

```go
ContentSecurityPolicy: "default-src 'self'"  // adjust for your provider's domains
```

### 5. `ClientSecret` Is Now Optional

If you're using a confidential client (most server apps), keep passing `ClientSecret` like
before. If you're a public client (SPA, CLI), you can omit it. No more fake errors about a
missing secret when you don't need one.

### 6. Logout Behavior

v1 had a hardcoded Azure logout URL fallback when `TenantID` was set. v2 uses OIDC
discovery—if your provider advertises an `end_session_endpoint`, Crooner uses it
automatically. If it doesn't, Crooner redirects to your `LogoutURLRedirect` directly.

No changes needed on your end if your provider supports OIDC discovery (Azure AD, Google,
Okta, etc. all do).

### 7. Remove `AuthConfig.TenantID` Access

If your code was reading `authConfig.TenantID` at runtime, that field is gone. If you need
the tenant ID for something else, store it in your own app config.

## Provider-Specific IssuerURL Examples

| Provider      | IssuerURL                                                              |
| ------------- | ---------------------------------------------------------------------- |
| Azure AD      | `https://login.microsoftonline.com/{tenant-id}/v2.0`                  |
| Google        | `https://accounts.google.com`                                         |
| Okta          | `https://{your-domain}.okta.com`                                      |
| Auth0         | `https://{your-domain}.auth0.com/`                                    |
| Keycloak      | `https://{host}/realms/{realm}`                                       |

## Quick Checklist

- [ ] Replace `TenantID` with `IssuerURL` in `AuthConfigParams`
- [ ] Update environment variables
- [ ] Remove any code reading `AuthConfig.TenantID`
- [ ] Update CSP headers if they referenced Azure domains
- [ ] Verify `ClientSecret` is still passed if you're a confidential client
- [ ] Run `go build ./...` — the compiler catches the rest
- [ ] Run your tests

That's the whole migration. You're still driving with the Crooner—just now the whole town
can ride. Don't let them make it look fake.

# PKCE Support in Kinde Go SDK

This document explains how to use the PKCE (Proof Key for Code Exchange) extension with the Authorization Code flow in the Kinde Go SDK.

## What is PKCE?

PKCE (RFC 7636) is a security extension for the OAuth 2.0 Authorization Code flow that prevents authorization code interception attacks. It's particularly important for public clients (applications that cannot securely store a client secret) although could be used for back-end authentication flow to enchance security.

## How PKCE Works

1. **Code Verifier Generation**: The client generates a random 43-character string
2. **Code Challenge Creation**: The client creates a SHA256 hash of the verifier (or uses the verifier directly for "plain" method)
3. **Authorization Request**: The challenge is sent with the authorization request
4. **Token Exchange**: The original verifier is sent when exchanging the authorization code for tokens

## Usage Examples

### Basic PKCE Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/kinde-oss/kinde-go/oauth2/authorization_code"
)

func main() {
    // Create authorization flow with PKCE enabled
    kindeAuthFlow, err := authorization_code.NewAuthorizationCodeFlow(
        "https://your-tenant.kinde.com",           // Kinde server URL
        "your-client-id",                         // Client ID
        "",                                        // No client secret for public client
        "http://localhost:8080/callback",         // Redirect URI
        authorization_code.WithSessionHooks(yourSessionHooks),
        authorization_code.WithPKCE(),             // Enable PKCE
    )

    if err != nil {
        log.Fatal("Failed to create auth flow:", err)
    }

    // Get the authorization URL (includes PKCE parameters)
    authURL := kindeAuthFlow.GetAuthURL()
    fmt.Println("Authorization URL:", authURL)

    // After user completes authentication and you receive the callback...
    ctx := context.Background()
    err = kindeAuthFlow.ExchangeCode(ctx, "received_code", "received_state")
    if err != nil {
        log.Fatal("Failed to exchange code:", err)
    }

    fmt.Println("Authentication successful!")
}

```

## Security Considerations

1. **Always use PKCE for public clients**: If your application cannot securely store a client secret, PKCE is essential
2. **Prefer S256 over plain**: The SHA256 challenge method is more secure than the plain method
3. **Store code verifier securely**: The code verifier should be stored in memory or secure storage during the authentication flow
4. **Validate state parameter**: Always validate the state parameter to prevent CSRF attacks

## Migration from Client Secret

If you're migrating from a confidential client (with client secret) to a public client (with PKCE):

1. Remove the client secret parameter (pass empty string)
2. Add `WithPKCE()` option
3. Ensure your Kinde application is configured as a public client
4. Test the authentication flow thoroughly

## API Reference

### New Options

- `WithPKCE()` - Enables PKCE with SHA256 challenge method
- `WithPKCEChallengeMethod(method string)` - Enables PKCE with custom challenge method

### Modified Methods

- `GetAuthURL()` - Now includes PKCE parameters when enabled
- `ExchangeCode()` - Now includes code verifier when PKCE is enabled

## Support

For issues or questions about PKCE implementation, please refer to:

- [RFC 7636 - PKCE Specification](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- Kinde documentation and support channels

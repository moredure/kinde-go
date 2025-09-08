# JWT Package

The `jwt` package provides comprehensive JWT (JSON Web Token) parsing, validation, and management capabilities for the Kinde Go SDK. This package is designed to work seamlessly with OAuth2 flows and provides flexible validation options.

## Features

- **Multiple Parsing Methods**: Parse JWT tokens from HTTP headers, strings, session storage, or OAuth2 tokens
- **Flexible Validation**: Configurable validation options for algorithm, audience, issuer, claims, and more
- **JWKS Support**: Built-in support for JSON Web Key Sets for token signature validation
- **Comprehensive Token Access**: Easy access to token claims, subject, issuer, audience, and other standard JWT fields
- **Error Handling**: Detailed validation error reporting

## Go Imports

```go
import (
    "github.com/kinde-oss/kinde-go/jwt" // required
)
```

## Quick Start

```go
import "github.com/kinde-oss/kinde-go/jwt"

// Parse and validate a JWT token
token, err := jwt.ParseFromString(
    "your.jwt.token.here",
    jwt.WillValidateWithJWKSUrl("https://your-domain.kinde.com/.well-known/jwks.json"),
    jwt.WillValidateAlgorithm("RS256"),
    jwt.WillValidateAudience("your-api-audience"),
)
if err != nil {
    // Handle error
}

// Check if token is valid
if token.IsValid() {
    // Token is valid, extract information
    subject := token.GetSubject()
    issuer := token.GetIssuer()
    // ... use token
}
```

## Parsing Methods

### ParseFromString

Parse a JWT token from a raw string:

```go
token, err := jwt.ParseFromString(
    rawTokenString,
    jwt.WillValidateWithJWKSUrl("https://your-domain.kinde.com/.well-known/jwks.json"),
)
```

### ParseFromAuthorizationHeader

Parse a JWT token from an HTTP Authorization header:

```go
// Expects: Authorization: Bearer <token>
token, err := jwt.ParseFromAuthorizationHeader(
    httpRequest,
    jwt.WillValidateWithJWKSUrl("https://your-domain.kinde.com/.well-known/jwks.json"),
)
```

### ParseFromSessionStorage

Parse a JWT token from session storage (JSON string):

```go
// Session storage contains JSON representation of oauth2.Token
token, err := jwt.ParseFromSessionStorage(
    sessionStorageString,
    jwt.WillValidateWithJWKSUrl("https://your-domain.kinde.com/.well-known/jwks.json"),
)
```

### ParseOAuth2Token

Parse a JWT token from an OAuth2 token:

```go
oauth2Token := &oauth2.Token{AccessToken: "your.jwt.token.here"}
token, err := jwt.ParseOAuth2Token(
    oauth2Token,
    jwt.WillValidateWithJWKSUrl("https://your-domain.kinde.com/.well-known/jwks.json"),
)
```

## Validation Options

### Signature Validation

#### JWKS URL Validation

Validate token signature using a JWKS endpoint:

```go
jwt.WillValidateWithJWKSUrl("https://your-domain.kinde.com/.well-known/jwks.json")
```

#### Public Key Validation

Validate token signature using a specific public key:

```go
jwt.WillValidateWithPublicKey(func(rawToken string) (*rsa.PublicKey, error) {
    // Return your public key
    return publicKey, nil
})
```

#### Custom Key Function

Use a custom function for key validation:

```go
jwt.WillValidateWithKeyFunc(func(token *golangjwt.Token) (interface{}, error) {
    // Custom key validation logic
    return key, nil
})
```

### Algorithm Validation

Validate the token's signing algorithm:

```go
// Default: RS256
jwt.WillValidateAlgorithm()

// Custom algorithms
jwt.WillValidateAlgorithm("RS256", "ES256")
```

### Audience Validation

Ensure the token contains the expected audience:

```go
jwt.WillValidateAudience("your-api-audience")
```

### Issuer Validation

Validate the token issuer:

```go
jwt.WillValidateIssuer("https://your-domain.kinde.com")
```

### Claims Validation

Custom validation for token claims:

```go
jwt.WillValidateClaims(func(claims golangjwt.MapClaims) (bool, error) {
    // Custom validation logic
    if customClaim, exists := claims["custom_field"]; exists {
        // Validate custom claim
        return true, nil
    }
    return false, fmt.Errorf("missing required claim")
})
```

### Time Validation

#### Clock Skew Tolerance

Allow for clock skew between servers:

```go
jwt.WillValidateWithClockSkew(30 * time.Second)
```

#### Custom Time Function

Use a custom time function (useful for testing):

```go
jwt.WillValidateWithTimeFunc(func() time.Time {
    return time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
})
```

## Token Information Access

Once you have a parsed token, you can access various properties:

### Basic Token Information

```go
// Check if token is valid
isValid := token.IsValid()

// Get raw OAuth2 token
rawToken := token.GetRawToken()

// Get validation errors
errors := token.GetValidationErrors()
```

### Token Types

```go
// Access token
accessToken, exists := token.GetAccessToken()

// ID token
idToken, exists := token.GetIdToken()

// Refresh token
refreshToken, exists := token.GetRefreshToken()
```

### JWT Claims

```go
// Get subject (sub claim)
subject := token.GetSubject()

// Get issuer (iss claim)
issuer := token.GetIssuer()

// Get audience (aud claim)
audience := token.GetAudience()

// Get all claims
claims := token.GetClaims()

// Get specific claim
if customValue, exists := claims["custom_field"]; exists {
    // Use custom value
}
```

### Serialization

```go
// Convert token to JSON string
jsonString, err := token.AsString()
```

## Common Use Cases

### 1. API Endpoint Protection

```go
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    token, err := jwt.ParseFromAuthorizationHeader(
        r,
        jwt.WillValidateWithJWKSUrl("https://your-domain.kinde.com/.well-known/jwks.json"),
        jwt.WillValidateAlgorithm("RS256"),
        jwt.WillValidateAudience("your-api-audience"),
    )

    if err != nil || !token.IsValid() {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Token is valid, proceed with request
    subject := token.GetSubject()
    // ... handle request
}
```

### 2. Session Token Validation

Note: You can also use the Authorization Code Middleware to automatically validate JWTs for protected routes in your application. This middleware streamlines the process of securing endpoints by handling token extraction and validation for you.

```go
func validateSession(sessionData string) (*jwt.Token, error) {
    return jwt.ParseFromSessionStorage(
        sessionData,
        jwt.WillValidateWithJWKSUrl("https://your-domain.kinde.com/.well-known/jwks.json"),
        jwt.WillValidateAlgorithm("RS256"),
        jwt.WillValidateIssuer("https://your-domain.kinde.com"),
    )
}
```

### 3. Custom Claims Validation

```go
func validateFavoriteColorIsBlue(token *jwt.Token) error {
    claims := token.GetClaims()

    if color, exists := claims["favorite_color"]; exists {
        if colorStr, ok := color.(string); ok {
            if colorStr == "blue" {
                return nil // Valid favorite color
            }
        }
    }

    return fmt.Errorf("favorite color is not blue")
}
```

### 4. Integration with OAuth2 Flows

```go
// In your OAuth2 flow configuration
kindeAuthFlow, err := authorization_code.NewAuthorizationCodeFlow(
    "https://your-domain.kinde.com",
    "client_id",
    "client_secret",
    "callback_url",
    authorization_code.WithTokenValidation(
        true,
        jwt.WillValidateAlgorithm("RS256"),
        jwt.WillValidateAudience("your-api-audience"),
        jwt.WillValidateClaims(func(claims golangjwt.MapClaims) (bool, error) {
            // Custom validation logic
            return true, nil
        }),
    ),
)
```

## Error Handling

The package provides comprehensive error handling:

```go
token, err := jwt.ParseFromString(rawToken, options...)
if err != nil {
    // Handle parsing/validation errors
    log.Printf("Token validation failed: %v", err)

    // Check specific validation errors
    if token != nil {
        for _, validationError := range token.GetValidationErrors() {
            log.Printf("Validation error: %v", validationError)
        }
    }
    return
}
```

## Best Practices

1. **Always Validate Signatures**: Use JWKS or public key validation to ensure token authenticity
2. **Validate Algorithm**: Explicitly specify allowed algorithms (default is RS256)
3. **Check Audience**: Validate that tokens are intended for your application
4. **Handle Errors Gracefully**: Check both parsing errors and validation errors
5. **Use Appropriate Clock Skew**: Allow reasonable time differences between servers
6. **Validate Custom Claims**: Implement business logic validation for custom claims

## Dependencies

- `github.com/golang-jwt/jwt/v5` - Core JWT functionality
- `github.com/MicahParks/jwkset` - JWKS client support
- `github.com/MicahParks/keyfunc/v3` - Key function utilities
- `golang.org/x/oauth2` - OAuth2 token support

## Examples

See the `jwt_test.go` file for comprehensive usage examples and test cases that demonstrate various validation scenarios and token handling patterns.

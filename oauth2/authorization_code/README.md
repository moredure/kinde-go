# Authorization Code Flow

The `authorization_code` package provides OAuth2 authorization code flow implementations for Go applications. This package is imported as `github.com/kinde-oss/kinde-go/oauth2/authorization_code`.

## Overview

The authorization code flow is a backend authorization flow that requires a client secret. It is designed to be used as a server-side auth flow and does not expose tokens to the browser. User sessions need to be managed by other means, for example via session cookies.

## Go Imports

```go
import (
    "github.com/kinde-oss/kinde-go/oauth2/authorization_code" // required
    "github.com/kinde-oss/kinde-go/jwt" // optional - for JWT token validation
)
```

## Standard Authorization Code Flow

### Basic Usage

```go
kindeAuthFlow, err := authorization_code.NewAuthorizationCodeFlow(
  "<issuer URL>",                                       // Kinde subdomain or any auth provider conforming to the spec
  "<client_id>", "<client_secret>", "<callback URL>",
  authorization_code.WithSessionHooks(<ISessionHooks implementation>),     // example of storage for gin framework is gin_kinde.UseKindeAuth(...)
  authorization_code.WithOffline(),                                        // adds offline scope and starts managing refresh tokens
  authorization_code.WithAudience("<your API audience>"),                  // requesting an API audience
  authorization_code.WithTokenValidation(
    true,                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                        // will validate the token alg is RS256
    jwt.WillValidateAudience("<your API audience>"),    // will confirm that received token includes correct audience
  ),
)
```

### Available Methods

| Method | Description | Parameters | Returns |
| --- | --- | --- | --- |
| `GetAuthURL` | Returns the URL to redirect the user to start the authentication pipeline. | none | `string` |
| `ExchangeCode` | Exchanges the authorization code for a token and establishes KindeContext. | ctx `context.Context`, authorizationCode `string`, receivedState `string` | `error` |
| `GetClient` | Returns an HTTP client for calling external services, automatically refreshing tokens if offline is requested. | ctx `context.Context` | `(*http.Client, error)` |
| `IsAuthenticated` | Checks if the user is authenticated. | ctx `context.Context` | `(bool, error)` |
| `Logout` | Clears local tokens and logs the user out. | none | `error` |
| `AuthorizationCodeReceivedHandler` | Helper handler middleware for the code exchanger. | w `http.ResponseWriter`, r `*http.Request` | none |

## Device Authorization Flow

The device authorization flow is an extension of the authorization code flow that separates token requester and receiver. It is best used for devices and environments with limited input capabilities, such as CLIs, TVs, etc.

### Basic Usage

```go
deviceFlow, err := authorization_code.NewDeviceAuthorizationFlow(
  "<issuer_domain>",                                    // Kinde subdomain or any auth provider conforming to the spec
  authorization_code.WithClientID("<your-client-id>"),  // optional, when business provides a default device application, otherwise required
  authorization_code.WithClientSecret("<your-client-secret>"), // optional (used when device flow is used against backend application with a secret)
  authorization_code.WithSessionHooks(<ISessionHooks implementation>),      // used for storing/retrieving tokens
  authorization_code.WithOffline(),                     // optional - include if you'd like to maintain refresh tokens and a long session
  authorization_code.WithTokenValidation(
    true,                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                        // will validate the token alg is RS256
  ),
)
```

### Available Methods

| Method | Description | Parameters | Returns |
| --- | --- | --- | --- |
| `StartDeviceAuth` | Starts the device authorization flow and returns the device authorization response. | ctx `context.Context` | `(*oauth2.DeviceAuthResponse, error)` |
| `ExchangeDeviceAccessToken` | Exchanges the device code for an access token. | ctx `context.Context`, da `*oauth2.DeviceAuthResponse`, opts `...oauth2.AuthCodeOption` | `error` |
| `GetClient` | Returns an HTTP client for calling external services, automatically refreshing tokens if offline is requested. | ctx `context.Context` | `(*http.Client, error)` |
| `IsAuthenticated` | Checks if the user is authenticated. | ctx `context.Context` | `(bool, error)` |
| `Logout` | Clears local tokens and logs the user out. | none | `error` |
| `GetToken` | Returns the token for the current session. | ctx `context.Context` | `(*jwt.Token, error)` |
| `InjectTokenMiddleware` | Middleware that injects the auth token into request context. | next `http.Handler` | `http.Handler` |

## Middleware

The authorization code flow package provides several middleware options to simplify integration with popular Go web frameworks and HTTP handlers.

### Built-in HTTP Handler Middleware

The `AuthorizationCodeReceivedHandler` method provides a built-in HTTP handler for processing OAuth2 callbacks:

```go
// Set up your callback route
http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
    kindeAuthFlow.AuthorizationCodeReceivedHandler(w, r)
})
```

This handler automatically:

- Extracts the authorization code and state from the request
- Validates the state parameter
- Exchanges the code for tokens
- Stores the tokens using your session hooks

### Gin Framework Middleware

For Gin applications, use the `gin_kinde` package which provides a complete middleware solution:

```go
import "github.com/kinde-oss/kinde-go/frameworks/gin_kinde"

func main() {
    router := gin.Default()

    // Set up session middleware
    store := sessions.NewStore(...)
    router.Use(sessions.Sessions("kinde-session", store))

    // Create a protected route group
    privateGroup := router.Group("/")

    // Apply Kinde authentication middleware
    gin_kinde.UseKindeAuth(privateGroup,
        "https://your-tenant.kinde.com",    // Kinde domain
        "your-client-id",                  // Client ID
        "your-client-secret",              // Client secret
        "http://localhost:8080",           // Base redirect URL
        authorization_code.WithPrompt("login"),
        authorization_code.WithOffline(),
    )

    // All routes in privateGroup are now protected
    privateGroup.GET("/profile", func(c *gin.Context) {
        // User is authenticated here
        c.JSON(200, gin.H{"message": "Authenticated!"})
    })

    router.Run(":8080")
}
```

The `gin_kinde.UseKindeAuth` middleware:

1. **Initializes the auth flow** for each request
2. **Handles the callback** at `/kinde/callback` automatically
3. **Protects all routes** in the group by checking authentication
4. **Redirects unauthenticated users** to the authorization URL
5. **Provides the Kinde client** in the Gin context for additional operations

### Custom Middleware Implementation

You can create custom middleware for other frameworks or specific use cases:

```go
func AuthMiddleware(kindeFlow *authorization_code.AuthorizationCodeFlow) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Check if user is authenticated
            isAuthenticated, err := kindeFlow.IsAuthenticated(r.Context())
            if err != nil || !isAuthenticated {
                // Redirect to authorization URL
                http.Redirect(w, r, kindeFlow.GetAuthURL(), http.StatusFound)
                return
            }

            // User is authenticated, continue to next handler
            next.ServeHTTP(w, r)
        })
    }
}

// Usage with standard http package
func main() {
    kindeFlow, _ := authorization_code.NewAuthorizationCodeFlow(...)

    mux := http.NewServeMux()
    mux.HandleFunc("/protected", protectedHandler)

    // Apply middleware
    handler := AuthMiddleware(kindeFlow)(mux)

    http.ListenAndServe(":8080", handler)
}
```

### Middleware Features

All middleware implementations provide:

- **Automatic authentication checking** on protected routes
- **Seamless redirects** to the authorization server
- **Session management** integration
- **Token validation** and refresh handling
- **Error handling** with appropriate HTTP status codes

### Middleware Configuration Options

When setting up middleware, you can pass the same options used in the authorization flow:

```go
gin_kinde.UseKindeAuth(privateGroup,
    kindeDomain,
    clientID,
    clientSecret,
    baseRedirectURL,
    authorization_code.WithOffline(),                    // Enable refresh tokens
    authorization_code.WithAudience("your-api"),        // Request specific audience
    authorization_code.WithPKCE(),                      // Enable PKCE for public clients
    authorization_code.WithTokenValidation(true),       // Enable token validation
)
```

These options are automatically applied to the authorization flow created by the middleware.

## Session Management

Both flows require session hooks to be implemented for token storage and retrieval. The session hooks interface allows you to customize how tokens are stored and retrieved based on your application's needs.

## Token Validation

Both flows support comprehensive token validation options:

- **Signature Validation**: Validates token signatures using JWKS
- **Algorithm Validation**: Ensures tokens use the expected algorithm (e.g., RS256)
- **Audience Validation**: Confirms tokens include the correct API audience
- **Custom Validation**: Additional validation rules can be implemented

## Offline Support

When using `WithOffline()`, the flows will:

- Request offline scope from the authorization server
- Manage refresh tokens automatically
- Maintain long-term sessions
- Automatically refresh expired access tokens

## Examples

For complete examples demonstrating these flows, see the `examples/` directory in the main repository:

- **Gin Chat Example**: Shows how to integrate authorization code flow with a Gin web application
- **CLI Example**: Demonstrates device authorization flow with secure token storage

## Security Considerations

- Always use HTTPS in production
- Implement proper session management
- Store tokens securely using the provided session hooks
- Validate tokens on each request
- Implement proper logout procedures
- Use appropriate scopes and audiences for your application

## Dependencies

This package requires Go 1.24+ and depends on the following packages:

- `github.com/kinde-oss/kinde-go/jwt` - For JWT token handling and validation
- Standard Go packages: `context`, `net/http`, `oauth2`

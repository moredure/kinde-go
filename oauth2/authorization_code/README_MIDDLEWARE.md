# Authorization Code Flow Middleware

This package provides HTTP middleware functionality for the Authorization Code Flow that automatically injects authentication tokens into the request context, making them available to downstream handlers.

## Overview

The middleware automatically:

1. Retrieves the current user's token from the session
2. Injects the token into the request context
3. Passes the request to the next handler
4. Handles cases where no token is available gracefully

## Usage

### Basic Middleware Usage

```go
package main

import (
    "net/http"
    "github.com/kinde-oss/kinde-go/oauth2/authorization_code"
)

func main() {
    // Create your authorization flow
    flow, err := authorization_code.NewAuthorizationCodeFlow(
        "https://your-domain.kinde.com",
        "your-client-id",
        "your-client-secret",
        "http://localhost:8080/callback",
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create your protected handler
    protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract token from context
        token, ok := authorization_code.TokenFromContext(r.Context())
        if !ok {
            http.Error(w, "Authentication required", http.StatusUnauthorized)
            return
        }

        // Use the token
        userID := token.GetSubject()
        claims := token.GetClaims()

        w.Write([]byte("Hello " + userID))
    })

    // Wrap with middleware
    protectedWithAuth := flow.InjectTokenMiddleware(protectedHandler)

    // Use in your mux/router
    mux := http.NewServeMux()
    mux.Handle("/protected", protectedWithAuth)

    http.ListenAndServe(":8080", mux)
}
```

### Using with Standard Library Mux

```go
func setupRoutes(flow authorization_code.IAuthorizationCodeFlow) *http.ServeMux {
    mux := http.NewServeMux()

    // Public routes
    mux.HandleFunc("/", homeHandler)
    mux.HandleFunc("/login", loginHandler)

    // Protected routes with middleware
    protectedMux := http.NewServeMux()
    protectedMux.HandleFunc("/profile", profileHandler)
    protectedMux.HandleFunc("/settings", settingsHandler)

    // Apply middleware to all protected routes
    protectedWithAuth := flow.Middleware(protectedMux)
    mux.Handle("/", protectedWithAuth)

    return mux
}
```

### Using with Gorilla Mux

```go
import (
    "github.com/gorilla/mux"
    "github.com/kinde-oss/kinde-go/oauth2/authorization_code"
)

func setupGorillaMux(flow authorization_code.IAuthorizationCodeFlow) *mux.Router {
    router := mux.NewRouter()

    // Public routes
    router.HandleFunc("/", homeHandler).Methods("GET")
    router.HandleFunc("/login", loginHandler).Methods("GET")

    // Protected routes
    protected := router.PathPrefix("/").Subrouter()
    protected.Use(flow.Middleware)
    protected.HandleFunc("/profile", profileHandler).Methods("GET")
    protected.HandleFunc("/settings", settingsHandler).Methods("GET")

    return router
}
```

### Custom Middleware with Token Access

You can create custom middleware that builds upon the Kinde middleware:

```go
func RequireScope(requiredScope string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get token from context (set by Kinde middleware)
            token, ok := authorization_code.TokenFromContext(r.Context())
            if !ok {
                http.Error(w, "Authentication required", http.StatusUnauthorized)
                return
            }

            // Check if user has required scope
            claims := token.GetClaims()
            // Check for array of scopes
            if scopes, ok := claims["scp"].([]interface{}); ok {
              for _, v := range scopes {
                if s, ok := v.(string); ok && s == requiredScope {
                  next.ServeHTTP(w, r)
                  return
                }
              }
            }
            // Check for space-delimited scope string
            if scopeStr, ok := claims["scope"].(string); ok {
              for _, s := range strings.Split(scopeStr, " ") {
                if s == requiredScope {
                  next.ServeHTTP(w, r)
                  return
                }
              }
            }

            http.Error(w, "Insufficient permissions", http.StatusForbidden)
        })
    }
}

// Usage
func setupScopedRoutes(flow authorization_code.IAuthorizationCodeFlow) *http.ServeMux {
    mux := http.NewServeMux()

    // Apply both middlewares
    adminHandler := RequireScope("admin")(flow.Middleware(adminOnlyHandler))
    mux.Handle("/admin", adminHandler)

    return mux
}
```

## API Reference

### Interface Methods

#### `Middleware(next http.Handler) http.Handler`

Creates middleware that injects the current user's token into the request context.

**Parameters:**

- `next` - The next HTTP handler in the chain

**Returns:**

- An HTTP handler that wraps the original handler with token injection

### Helper Functions

#### `TokenFromContext(ctx context.Context) (*jwt.Token, bool)`

Extracts the Kinde token from the request context.

**Parameters:**

- `ctx` - The request context

**Returns:**

- `*jwt.Token` - The token if found, nil otherwise
- `bool` - True if token was found, false otherwise

## Token Access in Handlers

Once the middleware is applied, you can access the token in your handlers:

```go
func profileHandler(w http.ResponseWriter, r *http.Request) {
    token, ok := authorization_code.TokenFromContext(r.Context())
    if !ok {
        http.Error(w, "Authentication required", http.StatusUnauthorized)
        return
    }

    // Access token information
    userID := token.GetSubject()
    claims := token.GetClaims()

    // Access specific claims
    if email, ok := claims["email"].(string); ok {
        // Use email
    }

    // Check if token is valid
    if !token.IsValid() {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Your business logic here
    w.Write([]byte("Profile for user: " + userID))
}
```

## Error Handling

The middleware handles various error scenarios gracefully:

1. **No token available**: Continues without setting token in context
2. **Session errors**: Continues without setting token in context
3. **Invalid tokens**: Continues without setting token in context

This allows your handlers to implement appropriate fallback behavior:

```go
func flexibleHandler(w http.ResponseWriter, r *http.Request) {
    token, ok := authorization_code.TokenFromContext(r.Context())
    if ok && token.IsValid() {
        // User is authenticated, show personalized content
        userID := token.GetSubject()
        w.Write([]byte("Welcome back, " + userID))
    } else {
        // User is not authenticated, show public content
        w.Write([]byte("Welcome, guest! Please log in for personalized content."))
    }
}
```

## Best Practices

1. **Always check if token exists**: Use the boolean return value from `TokenFromContext`
2. **Validate token validity**: Check `token.IsValid()` before using the token
3. **Handle missing tokens gracefully**: Provide fallback behavior for unauthenticated users
4. **Use appropriate HTTP status codes**: Return 401 for missing tokens, 403 for insufficient permissions
5. **Chain middleware carefully**: Apply the Kinde middleware before custom middleware that depends on it

## Examples

See `example_middleware.go` for complete working examples of how to use the middleware in different scenarios.

package authorization_code

import (
	"fmt"
	"net/http"

	"github.com/kinde-oss/kinde-go/jwt"
)

// ExampleMiddlewareUsage demonstrates how to use the new middleware
func ExampleMiddlewareUsage() {
	// This is an example of how to use the middleware in a real application

	// Create your authorization flow (this would be done in your app setup)
	// flow, err := NewAuthorizationCodeFlow(...)

	// Example handler that needs access to the token
	_ = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the token from the request context
		token, ok := TokenFromContext(r.Context())
		if !ok {
			http.Error(w, "No token found in context", http.StatusUnauthorized)
			return
		}

		// Use the token to access user information
		userID := token.GetSubject()
		claims := token.GetClaims()

		// Your business logic here
		fmt.Fprintf(w, "Hello %s! Claims: %v", userID, claims)
	})

	// Wrap your handler with the middleware
	// protectedHandler := flow.InjectTokenMiddleware(handler)

	// Use the protected handler in your mux/router
	// mux.Handle("/protected", protectedHandler)
}

// ExampleCustomMiddleware shows how to create custom middleware that uses the token
func ExampleCustomMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the token from context (set by the Kinde middleware)
		token, ok := TokenFromContext(r.Context())
		if !ok {
			// No token means the Kinde middleware didn't set one
			// This could happen if authentication failed or user is not logged in
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Example: Check if user has required scopes
		if !hasRequiredScopes(token, "admin") {
			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		// Continue to the next handler
		next.ServeHTTP(w, r)
	})
}

// hasRequiredScopes is a helper function to check if a token has required scopes
func hasRequiredScopes(token *jwt.Token, requiredScope string) bool {
	// This is a simplified example - you would implement your own scope checking logic
	// based on your application's requirements
	return false // Placeholder implementation
}

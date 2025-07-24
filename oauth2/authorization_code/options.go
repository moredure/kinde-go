package authorization_code

import (
	"slices"

	"github.com/kinde-oss/kinde-go/jwt"
)

type (
	Option func(*AuthorizationCodeFlow)
)

// Adds an arbitrary parameter to the list of parameters to request.
func WithAuthParameter(name, value string) Option {
	return func(s *AuthorizationCodeFlow) {
		if val, ok := s.authURLOptions[name]; ok {
			if !slices.Contains(val, value) {
				s.authURLOptions[name] = append(val, value)
			}
		} else {
			s.authURLOptions[name] = []string{value}
		}

	}
}

// Adds an audience to the list of audiences to request.
func WithAudience(audience string) Option {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("audience", audience)(s)
	}
}

// Adds an audience to the list of audiences to request.
func WithPrompt(prompt string) Option {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("prompt", prompt)(s)
	}
}

// Adds the offline scope to the list of scopes to request.
func WithOffline() Option {
	return func(s *AuthorizationCodeFlow) {
		WithAdditionalScope("offline")(s)
	}
}

// Adds the offline scope to the list of scopes to request.
func WithCustomStateGenerator(stateFunc func(*AuthorizationCodeFlow) string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.stateGenerator = stateFunc
	}
}

// Integrates with the session management
func WithSessionHooks(sessionHooks ISessionHooks) Option {
	return func(s *AuthorizationCodeFlow) {
		s.sessionHooks = sessionHooks
	}
}

// Integrates with the session management
func WithClientID(clientID string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.ClientID = clientID
	}
}

// Integrates with the session management
func WithClientSecret(clientSecret string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.ClientSecret = clientSecret
	}
}

// Adds a scopes to the list of scopes to request, replaces value with the provided.
func WithScopes(scopes ...string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = scopes
	}
}

// Adds a scopes to the list of scopes to request, adds scope to existing list.
func WithAdditionalScope(scope string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = append(s.config.Scopes, scope)
	}
}

// Adds options to validate the token.
func WithTokenValidation(isValidateJWKS bool, tokenOptions ...func(*jwt.Token)) Option {
	return func(s *AuthorizationCodeFlow) {

		if isValidateJWKS {
			s.tokenOptions = append(s.tokenOptions, jwt.WillValidateWithJWKSUrl(s.JWKS_URL))
		}

		s.tokenOptions = append(s.tokenOptions, tokenOptions...)
	}
}

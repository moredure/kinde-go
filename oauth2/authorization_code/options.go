package authorization_code

import (
	"context"
	"net/http"
	"net/url"
	"slices"

	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

// Adds an arbitrary parameter to the list of parameters to request.
func WithAuthParameter(name, value string) func(*AuthorizationCodeFlow) {
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
func WithAudience(audience string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("audience", audience)(s)
	}
}

// Adds an audience to the list of audiences to request.
func WithPrompt(prompt string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("prompt", prompt)(s)
	}
}

// Adds the offline scope to the list of scopes to request.
func WithOffline() func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		WithAdditionalScope("offline")
	}
}

// Adds the offline scope to the list of scopes to request.
func WithCustomStateGenerator(stateFunc func(*AuthorizationCodeFlow) string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.stateGenerator = stateFunc
	}
}

// Integrates with the session management
func WithSessionHooks(sessionHooks SessionHooks) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.sessionHooks = sessionHooks
	}
}

// Integrates with the session management
func WithClientID(clientID string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.config.ClientID = clientID
	}
}

// Integrates with the session management
func WithClientSecret(clientSecret string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.config.ClientSecret = clientSecret
	}
}

// Adds a scopes to the list of scopes to request, replaces value with the provided.
func WithScopes(scopes ...string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = scopes
	}
}

// Adds a scopes to the list of scopes to request, adds scope to existing list.
func WithAdditionalScope(scope string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = append(s.config.Scopes, scope)
	}
}

// Adds options to validate the token.
func WithTokenValidation(isValidateJWKS bool, tokenOptions ...func(*jwt.Token)) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {

		if isValidateJWKS {
			s.tokenOptions = append(s.tokenOptions, jwt.WillValidateWithJWKSUrl(s.JWKS_URL))
		}

		s.tokenOptions = append(s.tokenOptions, tokenOptions...)
	}
}

func (flow *AuthorizationCodeFlow) AuthorizationCodeReceived(w http.ResponseWriter, r *http.Request) {
	receivedState := r.URL.Query().Get("state")
	if flow.stateVerifier(flow, receivedState) {
		token, err := flow.config.Exchange(r.Context(), receivedState)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		parsedToken, err := jwt.ParseOAuth2Token(token, flow.tokenOptions...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if parsedToken.IsValid() {
			stringToken, err := parsedToken.AsString()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			flow.sessionHooks.SetToken(RawToken, stringToken)
		}
	}
}

// StartDeviceAuth retrieves the device authorization response.
// It returns the device authorization response or an error if the request fails.
// This is used for the device authorization flow.
func (flow *AuthorizationCodeFlow) StartDeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error) {
	return flow.config.DeviceAuth(ctx)
}

// Returns the URL to redirect the user to start authentication pipeline.
func (flow *AuthorizationCodeFlow) GetAuthURL() string {

	state := flow.stateGenerator(flow)
	url, _ := url.Parse(flow.config.AuthCodeURL(state))
	query := url.Query()
	for k, v := range flow.authURLOptions {
		if query.Get(k) == "" {
			query[k] = v
		}
	}
	url.RawQuery = query.Encode()
	return url.String()
}

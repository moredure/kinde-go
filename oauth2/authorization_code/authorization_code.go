package authorization_code

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

const (
	RawToken     TokenType = "raw_token"
	IDToken      TokenType = "id_token"
	AccessToken  TokenType = "access_token"
	RefreshToken TokenType = "refresh_token"
)

type (
	TokenType string

	SessionHooks interface {
		GetState() string
		SetState(state string)
		SetToken(t TokenType, token string)
		GetToken(t TokenType) string
		SetPostAuthRedirect(redirect string)
		GetPostAuthRedirect() string
	}

	// AuthorizationCodeFlow represents the authorization code flow.
	AuthorizationCodeFlow struct {
		config         oauth2.Config
		authURLOptions url.Values
		JWKS_URL       string
		tokenOptions   []func(*jwt.Token)
		sessionHooks   SessionHooks
		stateGenerator func(from *AuthorizationCodeFlow) string
		stateVerifier  func(flow *AuthorizationCodeFlow, receivedState string) bool
	}
)

// Creates a new AuthorizationCodeFlow with the given baseURL, clientID, clientSecret and options to authenticate backend applications.
func NewAuthorizationCodeFlow(baseURL string, clientID string, clientSecret string, callbackURL string,
	options ...func(*AuthorizationCodeFlow)) (*AuthorizationCodeFlow, error) {
	return newAuthorizationCodeflow(baseURL, clientID, clientSecret, callbackURL, options...)
}

func newAuthorizationCodeflow(baseURL string, clientID string, clientSecret string, callbackURL string,
	options ...func(*AuthorizationCodeFlow)) (*AuthorizationCodeFlow, error) {
	asURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := asURL.Hostname()

	if asURL.Port() != "" {
		host = fmt.Sprintf("%v:%v", host, asURL.Port())
	}

	client := &AuthorizationCodeFlow{
		JWKS_URL: fmt.Sprintf("%v://%v/.well-known/jwks", asURL.Scheme, host),
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				TokenURL: fmt.Sprintf("%v://%v/oauth2/token", asURL.Scheme, host),
				AuthURL:  fmt.Sprintf("%v://%v/oauth2/auth", asURL.Scheme, host),
			},
		},
		authURLOptions: url.Values{},
		stateGenerator: func(flow *AuthorizationCodeFlow) string {
			state := fmt.Sprintf("ks_%v", strings.ReplaceAll(uuid.NewString(), "-", ""))
			flow.sessionHooks.SetState(state)
			return state
		},
		stateVerifier: func(flow *AuthorizationCodeFlow, receivedState string) bool {
			return flow.sessionHooks.GetState() == receivedState
		},
	}

	for _, o := range options {
		o(client)
	}

	if client.sessionHooks == nil {
		panic("please connect your sesion management with WithSessionHooks")
	}

	return client, nil
}

// Exchanges the authorization code for a token and established KindeContext
func (flow *AuthorizationCodeFlow) ExchangeCode(ctx context.Context, authorizationCode string) error {
	token, err := flow.config.Exchange(ctx, authorizationCode)

	if err != nil {
		return err
	}

	flow.sessionHooks.SetToken(AccessToken, token.AccessToken)

	return nil
}

// Returns the client to make requests to the backend, will refreesh token if offline is requested.
func (flow *AuthorizationCodeFlow) GetClient(ctx context.Context, tokenSource oauth2.TokenSource) *http.Client {
	return oauth2.NewClient(ctx, tokenSource)
}

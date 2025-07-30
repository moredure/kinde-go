package client_credentials

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type (
	TokenType string

	ISessionHooks interface {
		// SetRawToken stores the raw token in the session.
		SetRawToken(token *oauth2.Token) error
		// GetRawToken retrieves the raw token from the session.
		GetRawToken() (*oauth2.Token, error)
	}

	IClientCredentialsFlow interface {
		GetClient(ctx context.Context) (*http.Client, error)
		GetToken(ctx context.Context) (*jwt.Token, error)
	}

	// ClientCredentialsFlow represents the client credentials flow.
	ClientCredentialsFlow struct {
		config       clientcredentials.Config
		tokenOptions []func(*jwt.Token)
		JWKS_URL     string
		sessionHooks ISessionHooks
	}
)

// Token implements oauth2.TokenSource.

// Creates a new ClientCredentialsFlow with the given baseURL, clientID, clientSecret and options to authenticate backend applications.
func NewClientCredentialsFlow(baseURL string, clientID string, clientSecret string, options ...Option) (IClientCredentialsFlow, error) {
	asURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := asURL.Hostname()
	if asURL.Port() != "" {
		host = fmt.Sprintf("%v:%v", host, asURL.Port())
	}
	flow := &ClientCredentialsFlow{
		config: clientcredentials.Config{
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			TokenURL:       fmt.Sprintf("%v://%v/%v", asURL.Scheme, host, "oauth2/token"),
			EndpointParams: map[string][]string{},
		},
		JWKS_URL: fmt.Sprintf("%v://%v/.well-known/jwks", asURL.Scheme, host),
	}

	for _, o := range options {
		o(flow)
	}

	if flow.sessionHooks == nil {
		return nil, fmt.Errorf("session hooks cannot be nil")
	}

	return flow, nil
}

// Returns the http client to be used to make requests.
func (flow *ClientCredentialsFlow) GetClient(ctx context.Context) (*http.Client, error) {
	tokenSource, err := flow.getTokenSource(ctx)
	if err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, tokenSource), nil
}

// Returns the token to be used to make requests.
func (flow *ClientCredentialsFlow) GetToken(ctx context.Context) (*jwt.Token, error) {

	ts, err := flow.getTokenSource(ctx)
	if err != nil {
		return nil, err
	}
	return ts.getValidatedToken(ctx)
}

func (flow *ClientCredentialsFlow) getTokenSource(_ context.Context) (sessionTokenSource, error) {
	return sessionTokenSource{flow: flow}, nil
}

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
	IClientCredentialsFlow interface {
		GetClient(ctx context.Context) *http.Client
		GetToken(ctx context.Context) (*jwt.Token, error)
	}

	// ClientCredentialsFlow represents the client credentials flow.
	ClientCredentialsFlow struct {
		config       clientcredentials.Config
		tokenOptions []func(*jwt.Token)
		JWKS_URL     string
		tokenSource  oauth2.TokenSource
	}
)

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
	client := &ClientCredentialsFlow{
		config: clientcredentials.Config{
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			TokenURL:       fmt.Sprintf("%v://%v/%v", asURL.Scheme, host, "oauth2/token"),
			EndpointParams: map[string][]string{},
		},
		JWKS_URL: fmt.Sprintf("%v://%v/.well-known/jwks", asURL.Scheme, host),
	}

	for _, o := range options {
		o(client)
	}

	client.tokenSource = client.config.TokenSource(context.Background())

	return client, nil
}

// Returns the http client to be used to make requests.
func (flow *ClientCredentialsFlow) GetClient(ctx context.Context) *http.Client {
	return flow.config.Client(ctx)
}

// Returns the token to be used to make requests.
func (flow *ClientCredentialsFlow) GetToken(ctx context.Context) (*jwt.Token, error) {

	token, err := flow.tokenSource.Token()
	if err != nil {
		return nil, err
	}
	return jwt.ParseOAuth2Token(token, flow.tokenOptions...)
}

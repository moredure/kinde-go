package kinde

import (
	"context"
	"fmt"
	"strings"

	"github.com/kinde-oss/kinde-go/kinde/management_api"
	"github.com/kinde-oss/kinde-go/oauth2/client_credentials"
)

type securitySource struct {
	clientCredentials client_credentials.IClientCredentialsFlow
}

// KindeBearerAuth implements management_api.SecuritySource.
func (s *securitySource) KindeBearerAuth(ctx context.Context, operationName management_api.OperationName) (management_api.KindeBearerAuth, error) {
	token, err := s.clientCredentials.GetToken(ctx)
	if err != nil {
		return management_api.KindeBearerAuth{}, err
	}

	rawToken := token.GetRawToken()
	if rawToken == nil {
		return management_api.KindeBearerAuth{}, fmt.Errorf("raw token is nil")
	}

	return management_api.KindeBearerAuth{
		Token: rawToken.AccessToken,
	}, nil
}

// NewManagementAPI creates a new management API client using the provided Kinde tenant URL, client ID, and client secret.
func NewManagementAPI(ctx context.Context, kindeTenantURL string, clientID string, clientSecret string, options ...client_credentials.Option) (*management_api.Client, error) {

	kindeTenantURL = strings.ToLower(kindeTenantURL)
	if kindeTenantURL == "" {
		return nil, fmt.Errorf("kindeTenantDomain cannot be empty")
	}

	options = append(options, client_credentials.WithKindeManagementAPI(kindeTenantURL))

	client, err := client_credentials.NewClientCredentialsFlow(kindeTenantURL, clientID, clientSecret, options...)
	if err != nil {
		return nil, err
	}

	managementApiClient, err := management_api.NewClient(kindeTenantURL, &securitySource{clientCredentials: client}, management_api.WithClient(client.GetClient(ctx)))
	return managementApiClient, err
}

package client_credentials

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/kinde-oss/kinde-go/jwt"
)

type (
	Option func(*ClientCredentialsFlow)
)

// Adds an arbitrary parameter to the list of parameters to request.
func WithAuthParameter(key, value string) Option {
	return func(s *ClientCredentialsFlow) {
		if params, ok := s.config.EndpointParams[key]; ok {
			s.config.EndpointParams[key] = append(params, value)
		} else {
			s.config.EndpointParams[key] = []string{value}
		}
	}
}

// Adds an arbitrary parameter to the list of parameters to request.
func WithAudience(audience string) Option {
	return func(s *ClientCredentialsFlow) {
		WithAuthParameter("audience", audience)(s)
	}
}

// Adds Kinde management API audience to the list of audiences to request.
func WithKindeManagementAPI(kindeDomain string) Option {
	return func(s *ClientCredentialsFlow) {

		asURL, err := url.Parse(kindeDomain)
		if err != nil {
			return
		}

		host := asURL.Hostname()
		if host == "" {
			host = kindeDomain
		}

		host = strings.TrimSuffix(host, ".kinde.com")

		managementApiAudience := fmt.Sprintf("https://%v.kinde.com/api", host)
		WithAuthParameter("audience", managementApiAudience)(s)
		WithAudience(managementApiAudience)(s)
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorithm(),
		)(s)
	}
}

// Adds options to validate the token.
func WithTokenValidation(isValidateJWKS bool, tokenOptions ...func(*jwt.Token)) Option {
	return func(s *ClientCredentialsFlow) {

		if isValidateJWKS {
			s.tokenOptions = append(s.tokenOptions, jwt.WillValidateWithJWKSUrl(s.JWKS_URL))
		}

		s.tokenOptions = append(s.tokenOptions, tokenOptions...)
	}
}

package client_credentials

import (
	"context"
	"fmt"
	"time"

	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

type (
	sessionTokenSource struct {
		flow *ClientCredentialsFlow
	}
)

func (t sessionTokenSource) validateToken(_ context.Context, token *oauth2.Token) (*jwt.Token, error) {
	parsedToken, err := jwt.ParseOAuth2Token(token, t.flow.tokenOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}
	return parsedToken, nil
}

func (t sessionTokenSource) getValidatedToken(_ context.Context) (*jwt.Token, error) {
	token, err := t.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return t.validateToken(context.Background(), token)

}

// Token implements oauth2.TokenSource.
func (t sessionTokenSource) Token() (*oauth2.Token, error) {
	cachedToken, _ := t.flow.sessionHooks.GetRawToken()

	ts := oauth2.ReuseTokenSourceWithExpiry(cachedToken, t.flow.config.TokenSource(context.Background()), time.Second*30)

	possiblyNewToken, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("token source: %w", err)
	}

	if _, err := t.validateToken(context.Background(), possiblyNewToken); err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	t.flow.sessionHooks.SetRawToken(possiblyNewToken)
	return possiblyNewToken, nil
}

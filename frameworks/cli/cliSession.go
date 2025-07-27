package cli

import (
	"encoding/json"
	"fmt"

	"github.com/99designs/keyring"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
	"golang.org/x/oauth2"
)

const (
	keyPrefix = "kinde"
)

type (
	cliSession struct {
		configFileName string
		keyring        keyring.Keyring
	}
)

// GetRawToken implements authorization_code.ISessionHooks.
func (c *cliSession) GetRawToken() (*oauth2.Token, error) {
	token, err := c.keyring.Get(fmt.Sprintf("%s_token", keyPrefix))
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	var t oauth2.Token
	if err := json.Unmarshal(token.Data, &t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	return &t, nil
}

// SetRawToken implements authorization_code.ISessionHooks.
func (c *cliSession) SetRawToken(token *oauth2.Token) error {
	t, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}
	c.keyring.Set(keyring.Item{
		Key:  fmt.Sprintf("%s_token", keyPrefix),
		Data: t,
	})
	return nil
}

// GetPostAuthRedirect implements authorization_code.SessionHooks.
func (c *cliSession) GetPostAuthRedirect() (string, error) {
	return "", fmt.Errorf("not supported in CLI session")
}

// GetState implements authorization_code.SessionHooks.
func (c *cliSession) GetState() (string, error) {
	return "", fmt.Errorf("not supported in CLI session")
}

// SetPostAuthRedirect implements authorization_code.SessionHooks.
func (c *cliSession) SetPostAuthRedirect(redirect string) error {
	return fmt.Errorf("not supported in CLI session")
}

// SetState implements authorization_code.SessionHooks.
func (c *cliSession) SetState(state string) error {
	return fmt.Errorf("not supported in CLI session")
}

func NewCliSession(serviceName string) (authorization_code.ISessionHooks, error) {
	ring, err := keyring.Open(keyring.Config{
		KeychainTrustApplication: true,
		ServiceName:              serviceName,
	})

	if err != nil {
		return nil, err
	}

	return &cliSession{
		keyring: ring,
	}, nil
}

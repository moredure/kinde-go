package cli

import (
	"fmt"

	"github.com/99designs/keyring"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
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

// GetPostAuthRedirect implements authorization_code.SessionHooks.
func (c *cliSession) GetPostAuthRedirect() (string, error) {
	return "", fmt.Errorf("not supported in CLI session")
}

// GetState implements authorization_code.SessionHooks.
func (c *cliSession) GetState() (string, error) {
	return "", fmt.Errorf("not supported in CLI session")
}

// GetToken implements authorization_code.SessionHooks.
func (c *cliSession) GetToken(t authorization_code.TokenType) (string, error) {
	token, err := c.keyring.Get(fmt.Sprintf("%s_%s", keyPrefix, t))
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	return string(token.Data), err
}

// SetPostAuthRedirect implements authorization_code.SessionHooks.
func (c *cliSession) SetPostAuthRedirect(redirect string) error {
	return fmt.Errorf("not supported in CLI session")
}

// SetState implements authorization_code.SessionHooks.
func (c *cliSession) SetState(state string) error {
	return fmt.Errorf("not supported in CLI session")
}

// SetToken implements authorization_code.SessionHooks.
func (c *cliSession) SetToken(t authorization_code.TokenType, token string) error {
	err := c.keyring.Set(keyring.Item{
		Key:  fmt.Sprintf("%s_%s", keyPrefix, t),
		Data: []byte(token),
	})
	return err
}

func NewCliSession(serviceName string) (authorization_code.SessionHooks, error) {
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

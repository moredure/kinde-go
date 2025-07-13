package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/99designs/keyring"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

const (
	keyPrefix = "kinde"
)

type (
	CliSession interface {
		authorization_code.SessionHooks
	}

	cliSession struct {
		configFileName string
		keyring        keyring.Keyring
		viper          *viper.Viper
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

func NewCliSession(serviceName string) (CliSession, error) {
	configType := "json"
	configFileName, err := detectConfigFileName(serviceName, configType)
	if err != nil {
		return nil, err
	}

	ring, err := keyring.Open(keyring.Config{
		KeychainTrustApplication: true,
		ServiceName:              serviceName,
	})

	if err != nil {
		return nil, err
	}

	viper := viper.New()

	viper.SetConfigType(configType)
	viper.SetConfigFile(configFileName)
	viper.SetConfigPermissions(os.FileMode(0600))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
	}

	err = viper.WriteConfig()
	if err != nil {
		return nil, err
	}

	return &cliSession{
		configFileName: configFileName,
		keyring:        ring,
		viper:          viper,
	}, nil
}

func detectConfigFileName(serviceName, configType string) (string, error) {
	configLocation := os.Getenv("XDG_CONFIG_HOME")
	if configLocation == "" {
		home, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		configLocation = filepath.Join(home, ".config")
	}
	configLocation = filepath.Join(configLocation, serviceName)

	err := os.MkdirAll(configLocation, os.ModePerm)
	if err != nil {
		return "", err
	}

	configLocation = filepath.Join(configLocation, fmt.Sprintf("config.%s", configType))

	return configLocation, nil
}

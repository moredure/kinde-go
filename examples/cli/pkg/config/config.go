package config

import (
	"fmt"

	"github.com/kinde-oss/kinde-go/frameworks/cli"
	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
)

var CLI_NAME = ""

type Config struct {
}

func NewDeviceAuthorizationFlow(issuerDomain string) (authorization_code.IDeviceAuthorizationFlow, error) {
	cliSession, err := cli.NewCliSession(CLI_NAME)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	deviceFlow, err := authorization_code.NewDeviceAuthorizationFlow(
		issuerDomain,
		authorization_code.WithSessionHooks(cliSession),
		authorization_code.WithOffline(),
		authorization_code.WithTokenValidation(
			true,
			jwt.WillValidateAlgorithm(),
			jwt.WillValidateIssuer(issuerDomain),
		),
	)
	if err != nil {
		return nil, err
	}
	return deviceFlow, nil
}

package cmd

import (
	"fmt"

	"github.com/kinde-oss/kinde-go/example-cli/pkg/config"
	"github.com/spf13/cobra"
)

type loginCmd struct {
	cmd         *cobra.Command
	kindeDomain string
}

func newloginCmd() *loginCmd {

	loginCmd := &loginCmd{}

	loginCmd.cmd = &cobra.Command{
		Use:   "login",
		Args:  nil,
		Short: "Version",
		RunE:  loginCmd.runLogin,
	}

	loginCmd.cmd.Flags().StringVar(&loginCmd.kindeDomain, "kinde-domain", "app.kinde.com", "Uses the kinde domain to connect to")

	return loginCmd
}

func (c *loginCmd) runLogin(cmd *cobra.Command, args []string) error {

	deviceFlow, err := config.NewDeviceAuthorizationFlow(c.kindeDomain)
	if err != nil {
		return err
	}

	deviceAuth, err := deviceFlow.StartDeviceAuth(c.cmd.Context())
	if err != nil {
		return err
	}

	fmt.Printf("Please open the following URL in your browser: %v \n", deviceAuth.VerificationURIComplete)
	fmt.Printf("Waiting for user to authorize... \n")

	err = deviceFlow.ExchangeDeviceAccessToken(c.cmd.Context(), deviceAuth)
	if err != nil {
		return err
	}
	token, err := deviceFlow.GetToken(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	fmt.Printf("Authenticated as %v\n", token.GetSubject())

	return nil
}

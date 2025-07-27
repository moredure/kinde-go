package cmd

import (
	"fmt"

	"github.com/kinde-oss/kinde-go/example-cli/pkg/config"
	"github.com/spf13/cobra"
)

type whoAmICmd struct {
	cmd         *cobra.Command
	kindeDomain string
}

func newWhoAmI() *whoAmICmd {
	whoAmICmd := &whoAmICmd{}

	whoAmICmd.cmd = &cobra.Command{
		Use:   "whoami",
		Args:  nil,
		Short: "Show current logged in user",
		RunE:  whoAmICmd.runWhoAmI,
	}

	whoAmICmd.cmd.Flags().StringVar(&whoAmICmd.kindeDomain, "kinde-domain", "app.kinde.com", "Uses the kinde domain to connect to")

	return whoAmICmd
}

func (c *whoAmICmd) runWhoAmI(cmd *cobra.Command, args []string) error {
	deviceFlow, err := config.NewDeviceAuthorizationFlow(c.kindeDomain)
	if err != nil {
		return err
	}

	if !deviceFlow.IsAuthenticated(cmd.Context()) {
		return fmt.Errorf("you are not logged in. Please run 'login' command first")
	}

	token, err := deviceFlow.GetToken(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	fmt.Printf("Authenticated as %v\n", token.GetSubject())

	return nil
}

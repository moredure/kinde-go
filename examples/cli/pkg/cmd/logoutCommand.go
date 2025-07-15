package cmd

import (
	"github.com/kinde-oss/kinde-go/example-cli/pkg/config"
	"github.com/spf13/cobra"
)

type logoutCmd struct {
	cmd         *cobra.Command
	kindeDomain string
}

func newLogoutCmd() *logoutCmd {
	logoutCmd := &logoutCmd{}

	logoutCmd.cmd = &cobra.Command{
		Use:   "logout",
		Short: "Logout and clear authentication tokens",
		RunE:  logoutCmd.runLogout,
	}

	return logoutCmd
}

func (c *logoutCmd) runLogout(cmd *cobra.Command, args []string) error {
	deviceFlow, err := config.NewDeviceAuthorizationFlow(c.kindeDomain)
	if err != nil {
		return err
	}

	err = deviceFlow.Logout()
	if err != nil {
	}

	cmd.Printf("Successfully logged out\n")
	return nil
}

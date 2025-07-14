package cmd

import (
	"context"

	"github.com/kinde-oss/kinde-cli/pkg/release"
	"github.com/kinde-oss/kinde-go/example-cli/pkg/config"
	"github.com/spf13/cobra"
)

func initLogging() {
}

func init() {
	cobra.OnInitialize(initLogging) //initialize stored creds, logging etc here later
	rootCmd.AddCommand(newVersionCmd().cmd)
	rootCmd.AddCommand(newloginCmd().cmd)
	rootCmd.AddCommand(newWhoAmI().cmd)
	rootCmd.AddCommand(newLogoutCmd().cmd)
}

var rootCmd = &cobra.Command{
	Use:           config.CLI_NAME,
	SilenceUsage:  true,
	SilenceErrors: true,
	Annotations:   map[string]string{},
	Version:       release.Branch,
	Short:         "Example CLI",
	Long:          "The example CLI with Kinde device auth.",
}

func Execute(context context.Context) {
	if err := rootCmd.ExecuteContext(context); err != nil {
		rootCmd.PrintErr(err)
	}
}

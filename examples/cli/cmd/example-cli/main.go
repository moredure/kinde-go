package main

import (
	"context"

	"github.com/kinde-oss/kinde-go/example-cli/pkg/cmd"
	"github.com/kinde-oss/kinde-go/example-cli/pkg/config"
)

func init() {
	config.CLI_NAME = "example-cli"
}

func main() {
	cmd.Execute(context.Background())
}

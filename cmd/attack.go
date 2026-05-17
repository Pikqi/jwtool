package cmd

import (
	"github.com/spf13/cobra"
)

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Automated JWT attack commands",
	Long:  `Send forged JWT tokens to a target endpoint and check if the attack succeeded.`,
}

func init() {
	attackCmd.PersistentFlags().String("url", "", "Target URL to send the forged token to (required)")
	attackCmd.PersistentFlags().String("cookie", "", "Send token as a cookie with this name instead of Authorization header")
	attackCmd.PersistentFlags().String("keyword", "", "Keyword to look for in response body to determine success")

	attackCmd.MarkPersistentFlagRequired("url")

	rootCmd.AddCommand(attackCmd)
}

/*
jwtool attack none       <JWT> --url --cookie --keyword
jwtool attack confusion  <JWT> --url --cookie --keyword --pubkey
jwtool attack brute      <JWT> --url --cookie --keyword --wordlist
jwtool attack auto       <JWT> --url --cookie --keyword --pubkey --wordlist
*/

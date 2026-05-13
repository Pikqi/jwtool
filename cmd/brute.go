package cmd

import (
	"fmt"

	"github.com/pikqi/jwtool/internal"
	"github.com/spf13/cobra"
)

var bruteCmd = &cobra.Command{
	Use:   "brute <jwt> <wordlist_path>",
	Short: "Brute force a JWT",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		output, err := internal.Bruteforce(args[0], args[1])
		if err != nil {
			return err
		}
		if output == "" {
			fmt.Println("Secret not found:")
		} else {
			fmt.Println("Secret found: " + output)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(bruteCmd)
}

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
		result, err := internal.Bruteforce(args[0], args[1])
		if err != nil {
			return err
		}

		fmt.Printf("Algorithm: %s\n", result.Alg)

		var triesPerSec float64
		if result.Duration.Seconds() > 0 {
			triesPerSec = float64(result.Tried) / result.Duration.Seconds()
		}

		if result.Secret == "" {
			fmt.Println("Secret not found")
		} else {
			fmt.Println("Secret found: " + result.Secret)
		}
		fmt.Printf("Tried %d secrets in %s (%.2f tries/s)\n", result.Tried, result.Duration, triesPerSec)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(bruteCmd)
}

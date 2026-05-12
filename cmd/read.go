package cmd

import (
	"fmt"

	"github.com/pikqi/jwtool/internal"
	"github.com/spf13/cobra"
)

var readCmd = &cobra.Command{
	Use:   "read <JWT>",
	Short: "See formatted JSON payload and header",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		claims, err := internal.ParseClaimsJson(args[0])
		if err != nil {
			return err
		}
		fmt.Println(claims)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(readCmd)
}

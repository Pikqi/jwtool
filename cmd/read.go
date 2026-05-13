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
		color, err := cmd.Flags().GetBool("color")
		if err != nil {
			return err
		}

		output, err := internal.FormatJWT(args[0], color)
		if err != nil {
			return err
		}
		fmt.Println(output)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(readCmd)
}

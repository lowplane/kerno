package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	versionpkg "github.com/optiqor/kerno/internal/version"
)

func newVersionCmd() *cobra.Command {
	var short bool
	var output string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := versionpkg.Get()

			// kerno version --short
			if short {
				fmt.Fprintln(cmd.OutOrStdout(), info.Short())
				return nil
			}

			// kerno version --output json
			if output == "json" {
				data, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					return err
				}

				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			// default output
			fmt.Fprintln(cmd.OutOrStdout(), info.String())
			return nil
		},
	}

	cmd.Flags().BoolVar(&short, "short", false, "Print only the version number")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "Output format: text or json")

	return cmd
}

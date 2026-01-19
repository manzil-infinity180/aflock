// Package verify implements attestation verification against policy.
package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Result represents the verification result.
type Result struct {
	Success       bool             `json:"success"`
	SessionID     string           `json:"sessionId"`
	PolicyName    string           `json:"policyName"`
	VerifiedAt    time.Time        `json:"verifiedAt"`
	Checks        []CheckResult    `json:"checks"`
	Metrics       *MetricsSummary  `json:"metrics,omitempty"`
	Errors        []string         `json:"errors,omitempty"`
	Warnings      []string         `json:"warnings,omitempty"`
}

// CheckResult represents a single verification check.
type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

// MetricsSummary summarizes session metrics.
type MetricsSummary struct {
	TotalTurns      int     `json:"totalTurns"`
	TotalToolCalls  int     `json:"totalToolCalls"`
	TotalTokensIn   int64   `json:"totalTokensIn"`
	TotalTokensOut  int64   `json:"totalTokensOut"`
	TotalCostUSD    float64 `json:"totalCostUSD"`
	Duration        string  `json:"duration"`
}

// Verifier verifies session attestations against policy.
type Verifier struct {
	stateManager *state.Manager
}

// NewVerifier creates a new verifier.
func NewVerifier() *Verifier {
	return &Verifier{
		stateManager: state.NewManager(""),
	}
}

// VerifySession verifies a session's attestations against its policy.
func (v *Verifier) VerifySession(sessionID string) (*Result, error) {
	result := &Result{
		SessionID:  sessionID,
		VerifiedAt: time.Now(),
		Success:    true,
	}

	// Load session state
	sessionState, err := v.stateManager.Load(sessionID)
	if err != nil {
		return nil, fmt.Errorf("load session state: %w", err)
	}
	if sessionState == nil {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	result.PolicyName = sessionState.Policy.Name

	// Build metrics summary
	if sessionState.Metrics != nil {
		result.Metrics = &MetricsSummary{
			TotalTurns:     sessionState.Metrics.Turns,
			TotalToolCalls: sessionState.Metrics.ToolCalls,
			TotalTokensIn:  sessionState.Metrics.TokensIn,
			TotalTokensOut: sessionState.Metrics.TokensOut,
			TotalCostUSD:   sessionState.Metrics.CostUSD,
			Duration:       time.Since(sessionState.StartedAt).Round(time.Second).String(),
		}
	}

	// Check 1: Policy limits (post-hoc)
	if sessionState.Policy.Limits != nil {
		evaluator := policy.NewEvaluator(sessionState.Policy)
		exceeded, limitName, msg := evaluator.CheckLimits(sessionState.Metrics, "post-hoc")
		if exceeded {
			result.Success = false
			result.Checks = append(result.Checks, CheckResult{
				Name:    "limits:" + limitName,
				Passed:  false,
				Message: msg,
			})
			result.Errors = append(result.Errors, msg)
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "limits:post-hoc",
				Passed: true,
			})
		}
	}

	// Check 2: Required attestations
	if len(sessionState.Policy.RequiredAttestations) > 0 {
		attestDir := v.stateManager.AttestationsDir(sessionID)
		for _, required := range sessionState.Policy.RequiredAttestations {
			found := v.findAttestation(attestDir, required)
			if !found {
				result.Success = false
				result.Checks = append(result.Checks, CheckResult{
					Name:    "attestation:" + required,
					Passed:  false,
					Message: fmt.Sprintf("Required attestation '%s' not found", required),
				})
				result.Errors = append(result.Errors, fmt.Sprintf("Missing attestation: %s", required))
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "attestation:" + required,
					Passed: true,
				})
			}
		}
	}

	// Check 3: Data flow violations
	if len(sessionState.Materials) > 0 {
		// Check if any actions were blocked due to data flow
		for _, action := range sessionState.Actions {
			if action.Decision == "deny" && strings.Contains(action.Reason, "Data flow") {
				result.Success = false
				result.Checks = append(result.Checks, CheckResult{
					Name:    "dataflow:" + action.ToolUseID,
					Passed:  false,
					Message: action.Reason,
				})
				result.Errors = append(result.Errors, action.Reason)
			}
		}
		if !containsCheckPrefix(result.Checks, "dataflow:") {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "dataflow",
				Passed: true,
			})
		}
	}

	// Check 4: Denied actions summary
	deniedCount := 0
	for _, action := range sessionState.Actions {
		if action.Decision == "deny" {
			deniedCount++
		}
	}
	if deniedCount > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%d actions were blocked by policy", deniedCount))
	}
	result.Checks = append(result.Checks, CheckResult{
		Name:    "actions",
		Passed:  true,
		Message: fmt.Sprintf("%d total actions, %d blocked", len(sessionState.Actions), deniedCount),
	})

	return result, nil
}

// VerifyLatestSession finds and verifies the most recent session.
func (v *Verifier) VerifyLatestSession() (*Result, error) {
	stateDir := filepath.Join(os.Getenv("HOME"), ".aflock", "sessions")
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return nil, fmt.Errorf("read sessions dir: %w", err)
	}

	var latestSession string
	var latestTime time.Time

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		statePath := filepath.Join(stateDir, entry.Name(), "state.json")
		info, err := os.Stat(statePath)
		if err != nil {
			continue
		}
		if info.ModTime().After(latestTime) {
			latestTime = info.ModTime()
			latestSession = entry.Name()
		}
	}

	if latestSession == "" {
		return nil, fmt.Errorf("no sessions found")
	}

	return v.VerifySession(latestSession)
}

// VerifyAttestation verifies a single attestation envelope.
func (v *Verifier) VerifyAttestation(envelopePath string, pol *aflock.Policy) error {
	data, err := os.ReadFile(envelopePath)
	if err != nil {
		return fmt.Errorf("read envelope: %w", err)
	}

	var envelope attestation.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("parse envelope: %w", err)
	}

	// Verify payload type
	if envelope.PayloadType != attestation.PayloadType {
		return fmt.Errorf("invalid payload type: %s", envelope.PayloadType)
	}

	// Decode and parse statement
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	var statement attestation.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return fmt.Errorf("parse statement: %w", err)
	}

	// Verify statement type
	if statement.Type != attestation.StatementType {
		return fmt.Errorf("invalid statement type: %s", statement.Type)
	}

	// TODO: Verify signature against functionaries
	// This requires the public keys/certs from the functionaries

	return nil
}

// ListSessions lists all available sessions.
func (v *Verifier) ListSessions() ([]SessionInfo, error) {
	stateDir := filepath.Join(os.Getenv("HOME"), ".aflock", "sessions")
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read sessions dir: %w", err)
	}

	var sessions []SessionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		state, err := v.stateManager.Load(entry.Name())
		if err != nil || state == nil {
			continue
		}

		sessions = append(sessions, SessionInfo{
			SessionID:  entry.Name(),
			PolicyName: state.Policy.Name,
			StartedAt:  state.StartedAt,
			Turns:      state.Metrics.Turns,
			ToolCalls:  state.Metrics.ToolCalls,
		})
	}

	return sessions, nil
}

// SessionInfo provides summary info about a session.
type SessionInfo struct {
	SessionID  string    `json:"sessionId"`
	PolicyName string    `json:"policyName"`
	StartedAt  time.Time `json:"startedAt"`
	Turns      int       `json:"turns"`
	ToolCalls  int       `json:"toolCalls"`
}

func (v *Verifier) findAttestation(dir, name string) bool {
	patterns := []string{
		filepath.Join(dir, name+".json"),
		filepath.Join(dir, name+".intoto.json"),
	}
	for _, p := range patterns {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	// Also check glob
	matches, _ := filepath.Glob(filepath.Join(dir, name+"*"))
	return len(matches) > 0
}

func containsCheckPrefix(checks []CheckResult, prefix string) bool {
	for _, c := range checks {
		if strings.HasPrefix(c.Name, prefix) {
			return true
		}
	}
	return false
}

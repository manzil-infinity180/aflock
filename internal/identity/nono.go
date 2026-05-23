// Package identity provides agent identity derivation based on transitive workload identity.
package identity

import (
	"os"
	"path/filepath"
	"strings"
)

// NonoSupervisor describes a detected nono supervisor process.
type NonoSupervisor struct {
	PID     int
	Command string
}

// DetectNonoSupervisor walks the parent process tree and returns the first
// detected nono supervisor process.
func DetectNonoSupervisor() (*NonoSupervisor, error) {
	ppid := os.Getppid()
	if ppid <= 1 {
		return nil, nil
	}

	pids := getProcessChain(ppid)
	inspected := false
	var lastErr error

	for _, pid := range pids {
		cmd, err := getProcessCommand(pid)
		if err != nil {
			lastErr = err
			continue
		}
		inspected = true
		if isNonoSupervisorCommand(cmd) {
			return &NonoSupervisor{PID: pid, Command: cmd}, nil
		}
	}

	if !inspected && lastErr != nil {
		return nil, lastErr
	}

	return nil, nil
}

func isNonoSupervisorCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	if lower == "" {
		return false
	}

	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return false
	}

	base := filepath.Base(fields[0])
	if base == "nono" || base == "nono-supervisor" {
		return true
	}

	return strings.Contains(lower, "nono-supervisor")
}

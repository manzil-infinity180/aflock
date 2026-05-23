package identity

import "testing"

func TestIsNonoSupervisorCommand(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{
			name:     "nono binary",
			command:  "/usr/local/bin/nono run --profile=claude-code",
			expected: true,
		},
		{
			name:     "nono supervisor binary",
			command:  "nono-supervisor --profile=claude-code",
			expected: true,
		},
		{
			name:     "nono supervisor substring",
			command:  "/opt/tools/nono-supervisor --config=/tmp/nono.json",
			expected: true,
		},
		{
			name:     "non-nono command",
			command:  "/usr/bin/python3 /tmp/script.py",
			expected: false,
		},
		{
			name:     "similar name",
			command:  "/usr/bin/nonoise --verbose",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isNonoSupervisorCommand(test.command); got != test.expected {
				t.Fatalf("expected %v, got %v", test.expected, got)
			}
		})
	}
}

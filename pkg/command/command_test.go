package command

import (
	"syscall"
	"testing"
)

func TestRunOnHost(t *testing.T) {
	// Test successful command
	output, err := RunOnHost([]string{"echo", "test"}, true)
	if err != nil {
		t.Errorf("RunOnHost() failed: %v", err)
	}
	if output != "test" {
		t.Errorf("Expected 'test', got '%s'", output)
	}

	// Test command without output
	_, err = RunOnHost([]string{"true"}, false)
	if err != nil {
		t.Errorf("RunOnHost() should succeed: %v", err)
	}

	// Test failing command
	_, err = RunOnHost([]string{"false"}, false)
	if err == nil {
		t.Error("RunOnHost() should fail for 'false' command")
	}
}

func TestSetns(t *testing.T) {
	// Test setns with invalid file descriptor
	err := Setns(-1, 0)
	if err == nil {
		t.Error("Expected error for invalid file descriptor")
	}
}

func TestRunInNamespace(t *testing.T) {
	// Test with invalid PID
	err := RunInNamespace(-1, 0, func() error {
		return nil
	})
	if err == nil {
		t.Error("Expected error for invalid PID")
	}
}

func TestGetNamespaceType(t *testing.T) {
	tests := []struct {
		nstype   int
		expected string
	}{
		{syscall.CLONE_NEWNET, "net"},
		{syscall.CLONE_NEWNS, "mnt"},
		{syscall.CLONE_NEWUTS, "uts"},
		{999, "net"}, // default case
	}
	
	for _, test := range tests {
		result := getNamespaceType(test.nstype)
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

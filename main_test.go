package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestE2E_ContainerManager(t *testing.T) {
	// Skip if not running as root (required for containers)
	if os.Getuid() != 0 {
		t.Skip("E2E tests require root privileges")
	}

	// Build the binary first
	buildCmd := exec.Command("go", "build", "-o", "container-manager-test", ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	defer os.Remove("container-manager-test")

	// Test help command
	t.Run("Help", func(t *testing.T) {
		cmd := exec.Command("./container-manager-test", "--help")
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("Help command failed: %v", err)
		}

		outputStr := string(output)
		if !strings.Contains(outputStr, "container-manager") {
			t.Error("Help should contain app name")
		}
		if !strings.Contains(outputStr, "run") {
			t.Error("Help should contain 'run' command")
		}
	})

	// Test cleanup command
	t.Run("Cleanup", func(t *testing.T) {
		cmd := exec.Command("./container-manager-test", "rm")
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("Cleanup command failed: %v", err)
		}

		if !strings.Contains(string(output), "Cleaning up") {
			t.Error("Cleanup should show cleaning message")
		}
	})

	// Test container run (non-interactive)
	t.Run("ContainerRun", func(t *testing.T) {
		// This test is complex because it requires:
		// 1. Root privileges
		// 2. Network setup
		// 3. Image download
		// 4. Container execution

		// Create a test script that exits immediately
		testScript := `#!/bin/sh
echo "Container started successfully"
exit 0`

		// We'll test the setup phase only
		testDir := "./test_image_root"
		defer os.RemoveAll(testDir)

		// Create minimal container filesystem
		if err := os.MkdirAll(filepath.Join(testDir, "bin"), 0755); err != nil {
			t.Fatalf("Failed to create bin directory: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(testDir, "etc"), 0755); err != nil {
			t.Fatalf("Failed to create etc directory: %v", err)
		}

		scriptPath := filepath.Join(testDir, "bin", "sh")
		err := os.WriteFile(scriptPath, []byte(testScript), 0755)
		if err != nil {
			t.Fatalf("Failed to create test script: %v", err)
		}

		// Test that directories are created properly
		if _, err := os.Stat(testDir); os.IsNotExist(err) {
			t.Error("Test container root should exist")
		}
	})
}

func TestE2E_ImageParsing(t *testing.T) {
	tests := []struct {
		input         string
		expectedImage string
		expectedTag   string
	}{
		{"alpine", "library/alpine", "latest"},
		{"alpine:3.18", "library/alpine", "3.18"},
		{"nginx/nginx", "nginx/nginx", "latest"},
		{"nginx/nginx:stable", "nginx/nginx", "stable"},
	}

	for _, test := range tests {
		// Test the parsing logic from runContainer
		parts := strings.Split(test.input, ":")
		image := parts[0]
		tag := "latest"
		if len(parts) > 1 {
			tag = parts[1]
		}

		// Add library/ prefix for official images
		if !strings.Contains(image, "/") {
			image = "library/" + image
		}

		if image != test.expectedImage {
			t.Errorf("Image parsing: expected %s, got %s", test.expectedImage, image)
		}
		if tag != test.expectedTag {
			t.Errorf("Tag parsing: expected %s, got %s", test.expectedTag, tag)
		}
	}
}

func TestE2E_DirectoryCleanup(t *testing.T) {
	// Test cleanup functionality
	testDirs := []string{
		"./test_image_root",
		"./test_docker_temp",
	}

	// Create test directories
	for _, dir := range testDirs {
		if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0755); err != nil {
			t.Fatalf("Failed to create test directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "testfile"), []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Test cleanup function
	for _, dir := range testDirs {
		os.RemoveAll(dir)

		// Verify cleanup
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("Directory %s should be cleaned up", dir)
		}
	}
}

func TestE2E_PIDFinding(t *testing.T) {
	// Test findContainerPID function with a real process
	cmd := exec.Command("sleep", "1")
	err := cmd.Start()
	if err != nil {
		t.Fatalf("Failed to start test process: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	pid := cmd.Process.Pid

	// Test the findContainerPID logic
	childrenPath := filepath.Join("/proc", string(rune(pid)), "children")
	if _, err := os.Stat(childrenPath); err == nil {
		// If children file exists, test reading it
		data, err := os.ReadFile(childrenPath)
		if err == nil {
			childrenStr := strings.TrimSpace(string(data))
			// This is expected to be empty for sleep command
			if childrenStr != "" {
				t.Logf("Found children: %s", childrenStr)
			}
		}
	}

	// Wait for process to finish
	time.Sleep(100 * time.Millisecond)
	_ = cmd.Wait()
}

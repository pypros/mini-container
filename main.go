package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"container-manager/pkg/downloader"
	"container-manager/pkg/network"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go run [image]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		image := "alpine:latest"
		if len(os.Args) > 2 {
			image = os.Args[2]
		}
		runContainer(image)
	case "rm":
		cleanup()

	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}

func runContainer(imageArg string) {
	containerRoot := "./my_image_root"
	customBridge := "custom-bridge-0"

	// Parse image
	parts := strings.Split(imageArg, ":")
	image := parts[0]
	tag := "latest"
	if len(parts) > 1 {
		tag = parts[1]
	}

	// Add library/ prefix for official images
	if !strings.Contains(image, "/") {
		image = "library/" + image
	}

	// Download image if not exists
	if _, err := os.Stat(containerRoot); os.IsNotExist(err) {
		fmt.Println("Downloading image...")
		if err := downloader.DownloadImage(image, tag, "amd64", containerRoot); err != nil {
			fmt.Printf("Failed to download image: %v\n", err)
			return
		}
	}

	// Generate network config
	netConfig, err := network.GenerateNetworkConfig()
	if err != nil {
		fmt.Printf("Failed to generate network config: %v\n", err)
		return
	}

	// Get host interface
	hostIface, err := network.HostInterface(customBridge)
	if err != nil {
		fmt.Printf("Failed to get host interface: %v\n", err)
		return
	}

	// Setup cgroups
	cgroupPath := "/sys/fs/cgroup/my_custom_container"
	os.MkdirAll(cgroupPath, 0755)
	os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("256M"), 0644)
	os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("50000 100000"), 0644)

	// Mount /dev using syscall
	devPath := filepath.Join(containerRoot, "dev")
	if err := syscall.Mount("none", devPath, "devtmpfs", 0, ""); err != nil {
		fmt.Printf("Warning: failed to mount /dev: %v\n", err)
	}

	// Start simple shell in container
	cmd := exec.Command("/bin/sh", "-i")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS | syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		Chroot:      containerRoot,
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("Failed to start container: %v\n", err)
		return
	}

	pid := cmd.Process.Pid
	fmt.Printf("Container PID: %d\n", pid)

	// Find actual container PID (child process in new PID namespace)
	containerPID := findContainerPID(pid)
	fmt.Printf("Container PID children: %d\n", pid)
	if containerPID != 0 {
		fmt.Printf("Found container child PID: %d\n", containerPID)
		pid = containerPID
	}

	// Add to cgroup
	os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644)

	// Configure container namespace using nsenter
	go configureContainerNamespace(pid, containerRoot)

	// Setup network
	network.Create(pid, customBridge, containerRoot, netConfig.BridgeIP, netConfig.ContainerNetwork, netConfig.ContainerIP, hostIface)

	fmt.Println("Container started. Type 'exit' to quit.")
	cmd.Wait()

	// Cleanup
	network.Remove(customBridge, netConfig.BridgeIP, netConfig.ContainerNetwork, hostIface)
	cleanupContainer(pid, cgroupPath, containerRoot)
}

func cleanupContainer(pid int, cgroupPath, containerRoot string) {
	// Unmount filesystems using syscalls (ignore errors)
	syscall.Unmount(filepath.Join(containerRoot, "dev"), 0)
	syscall.Unmount(filepath.Join(containerRoot, "proc"), 0)
	syscall.Unmount(filepath.Join(containerRoot, "sys"), 0)

	// Remove directories
	os.RemoveAll(containerRoot)
	os.RemoveAll(cgroupPath)
	os.RemoveAll(".docker_temp")
}

func findContainerPID(parentPID int) int {
	// Read /proc/PID/children to find child processes
	childrenPath := fmt.Sprintf("/proc/%d/children", parentPID)
	data, err := os.ReadFile(childrenPath)
	if err != nil {
		return 0
	}

	// Parse child PIDs
	childrenStr := strings.TrimSpace(string(data))
	if childrenStr == "" {
		return 0
	}

	pids := strings.Fields(childrenStr)
	if len(pids) > 0 {
		if childPID, err := strconv.Atoi(pids[0]); err == nil {
			return childPID
		}
	}

	return 0
}

func configureContainerNamespace(pid int, containerRoot string) {
	// Mount proc and sys using nsenter
	exec.Command("nsenter", "-t", strconv.Itoa(pid), "-m", "mount", "-t", "proc", "proc", "/proc").Run()
	exec.Command("nsenter", "-t", strconv.Itoa(pid), "-m", "mount", "-t", "sysfs", "sys", "/sys").Run()
	exec.Command("nsenter", "-t", strconv.Itoa(pid), "-u", "hostname", "my-container").Run()
}

func cleanup() {
	fmt.Println("Cleaning up resources...")
	cleanupContainer(0, "/sys/fs/cgroup/my_custom_container", "./my_image_root")
	fmt.Println("Cleanup complete.")
}

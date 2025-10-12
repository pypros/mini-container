package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"container-manager/pkg/command"
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

	// Mount /dev
	command.RunOnHost([]string{"mount", "-t", "devtmpfs", "none", filepath.Join(containerRoot, "dev")}, false)

	// Create init script with Go syscalls where possible
	initScript := `
		mount -t proc proc /proc
		mount -t sysfs sys /sys
		hostname my-container
		while [ ! -f /network_ready ]; do sleep 0.1; done
		rm -f /network_ready
		export HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TERM=xterm
		exec /bin/sh -i
	`

	cmd := exec.Command("/bin/sh", "-c", initScript)
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

	// Add to cgroup
	os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644)

	// Setup network
	network.Create(pid, customBridge, containerRoot, netConfig.BridgeIP, netConfig.ContainerNetwork, netConfig.ContainerIP, hostIface)

	// Signal network ready
	os.WriteFile(filepath.Join(containerRoot, "network_ready"), []byte(""), 0644)

	fmt.Println("Container started. Type 'exit' to quit.")
	cmd.Wait()

	// Cleanup
	network.Remove(customBridge, netConfig.BridgeIP, netConfig.ContainerNetwork, hostIface)
	cleanupContainer(pid, cgroupPath, containerRoot)
}

func cleanupContainer(pid int, cgroupPath, containerRoot string) {
	// Unmount filesystems (ignore errors like Python version)
	exec.Command("umount", filepath.Join(containerRoot, "dev")).Run()
	exec.Command("umount", filepath.Join(containerRoot, "proc")).Run()
	exec.Command("umount", filepath.Join(containerRoot, "sys")).Run()

	// Remove directories
	os.RemoveAll(containerRoot)
	os.RemoveAll(cgroupPath)
	os.RemoveAll(".docker_temp")
}

func cleanup() {
	fmt.Println("Cleaning up resources...")
	cleanupContainer(0, "/sys/fs/cgroup/my_custom_container", "./my_image_root")
	fmt.Println("Cleanup complete.")
}

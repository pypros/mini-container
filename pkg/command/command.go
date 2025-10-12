package command

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

func RunOnHost(cmd []string, pipeOutput bool) (string, error) {
	command := exec.Command(cmd[0], cmd[1:]...)

	if pipeOutput {
		output, err := command.Output()
		return strings.TrimSpace(string(output)), err
	}

	return "", command.Run()
}

// setns syscall wrapper
func Setns(fd int, nstype int) error {
	const SYS_SETNS = 308
	_, _, errno := syscall.Syscall(SYS_SETNS, uintptr(fd), uintptr(nstype), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// RunInNamespace executes function in specified namespace
func RunInNamespace(pid int, nstype int, fn func() error) error {
	nsPath := fmt.Sprintf("/proc/%d/ns/%s", pid, getNamespaceType(nstype))
	if fd, err := syscall.Open(nsPath, syscall.O_RDONLY, 0); err == nil {
		defer syscall.Close(fd)
		if Setns(fd, nstype) == nil {
			return fn()
		}
	}
	return fmt.Errorf("failed to enter namespace")
}

func getNamespaceType(nstype int) string {
	switch nstype {
	case syscall.CLONE_NEWNET:
		return "net"
	case syscall.CLONE_NEWNS:
		return "mnt"
	case syscall.CLONE_NEWUTS:
		return "uts"
	default:
		return "net"
	}
}

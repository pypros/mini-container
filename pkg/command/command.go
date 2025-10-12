package command

import (
	"fmt"
	"os/exec"
	"strings"
)

func RunOnHost(cmd []string, pipeOutput bool) (string, error) {
	command := exec.Command(cmd[0], cmd[1:]...)
	
	if pipeOutput {
		output, err := command.Output()
		return strings.TrimSpace(string(output)), err
	}
	
	return "", command.Run()
}

func RunOnContainer(containerPID int, cmd, containerRoot string) (string, error) {
	nsenterCmd := []string{
		"nsenter", "-t", fmt.Sprintf("%d", containerPID),
		"--mount", "--net", "--uts",
		fmt.Sprintf("--root=%s", containerRoot),
		"/bin/sh", "-c", cmd,
	}
	
	return RunOnHost(nsenterCmd, true)
}
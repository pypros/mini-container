package network

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"container-manager/pkg/command"
)

type NetworkConfig struct {
	ContainerNetwork string
	BridgeIP         string
	ContainerIP      string
}

func GenerateNetworkConfig() (*NetworkConfig, error) {
	usedSubnets, err := getUsedSubnets()
	if err != nil {
		return nil, err
	}

	for i := 0; i < 5; i++ {
		secondOctet := rand.Intn(16) + 16 // 16-31
		networkBase := fmt.Sprintf("172.%d.0.0/16", secondOctet)
		
		_, newNet, err := net.ParseCIDR(networkBase)
		if err != nil {
			continue
		}

		conflicting := false
		for _, usedNet := range usedSubnets {
			if newNet.Contains(usedNet.IP) || usedNet.Contains(newNet.IP) {
				conflicting = true
				break
			}
		}

		if !conflicting {
			bridgeIP := fmt.Sprintf("172.%d.0.1/16", secondOctet)
			containerIP := fmt.Sprintf("172.%d.0.2/16", secondOctet)
			
			return &NetworkConfig{
				ContainerNetwork: networkBase,
				BridgeIP:         bridgeIP,
				ContainerIP:      containerIP,
			}, nil
		}
	}

	return nil, fmt.Errorf("cannot find free subnet")
}

func getUsedSubnets() ([]*net.IPNet, error) {
	output, err := command.RunOnHost([]string{"ip", "route", "show"}, true)
	if err != nil {
		return nil, err
	}

	var subnets []*net.IPNet
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})`)
	
	for _, line := range strings.Split(output, "\n") {
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			_, subnet, err := net.ParseCIDR(matches[1])
			if err == nil {
				subnets = append(subnets, subnet)
			}
		}
	}

	return subnets, nil
}

func HostInterface(customBridge string) (string, error) {
	output, err := command.RunOnHost([]string{"ip", "route", "show", "default"}, true)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`dev\s+(\S+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		iface := matches[1]
		if iface != "lo" && iface != customBridge {
			return iface, nil
		}
	}

	return "", fmt.Errorf("no suitable interface found")
}

func Create(containerPID int, customBridge, containerRoot, bridgeIP, containerNetwork, containerIP, hostInterface string) error {
	vethHost := fmt.Sprintf("h%d", containerPID)
	vethGuest := fmt.Sprintf("c%d", containerPID)
	gatewayIP := strings.Split(bridgeIP, "/")[0]

	// Enable IP forwarding
	command.RunOnHost([]string{"sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"}, false)

	// Create bridge
	command.RunOnHost([]string{"ip", "link", "add", "name", customBridge, "type", "bridge"}, false)
	command.RunOnHost([]string{"ip", "link", "set", customBridge, "up"}, false)
	command.RunOnHost([]string{"ip", "addr", "add", bridgeIP, "dev", customBridge}, false)

	// Create VETH pair
	command.RunOnHost([]string{"ip", "link", "add", "name", vethHost, "type", "veth", "peer", "name", vethGuest}, false)
	command.RunOnHost([]string{"ip", "link", "set", vethHost, "master", customBridge}, false)
	command.RunOnHost([]string{"ip", "link", "set", vethHost, "up"}, false)

	// Move VETH to namespace
	command.RunOnHost([]string{"ip", "link", "set", vethGuest, "netns", strconv.Itoa(containerPID)}, false)

	// Configure NAT
	command.RunOnHost([]string{"iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1", "-s", containerNetwork, "-o", hostInterface, "-j", "MASQUERADE"}, false)
	command.RunOnHost([]string{"iptables", "-w", "-I", "FORWARD", "1", "-i", customBridge, "-o", hostInterface, "-j", "ACCEPT"}, false)
	command.RunOnHost([]string{"iptables", "-w", "-I", "FORWARD", "1", "-i", hostInterface, "-o", customBridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, false)

	// Write resolv.conf
	resolvPath := filepath.Join(containerRoot, "etc", "resolv.conf")
	os.MkdirAll(filepath.Dir(resolvPath), 0755)
	os.WriteFile(resolvPath, []byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n"), 0644)

	// Configure network inside container
	containerCmd := fmt.Sprintf("ip link set lo up && ip link set %s up && ip addr add %s dev %s && ip route add default via %s", 
		vethGuest, containerIP, vethGuest, gatewayIP)
	command.RunOnContainer(containerPID, containerCmd, containerRoot)

	return nil
}

func Remove(customBridge, bridgeIP, containerNetwork, hostInterface string) error {
	// Remove iptables rules
	command.RunOnHost([]string{"iptables", "-w", "-t", "nat", "-D", "POSTROUTING", "-s", containerNetwork, "-o", hostInterface, "-j", "MASQUERADE"}, false)
	command.RunOnHost([]string{"iptables", "-w", "-D", "FORWARD", "-i", customBridge, "-o", hostInterface, "-j", "ACCEPT"}, false)
	command.RunOnHost([]string{"iptables", "-w", "-D", "FORWARD", "-i", hostInterface, "-o", customBridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, false)

	// Remove bridge
	command.RunOnHost([]string{"ip", "addr", "del", bridgeIP, "dev", customBridge}, false)
	command.RunOnHost([]string{"ip", "link", "set", customBridge, "down"}, false)
	command.RunOnHost([]string{"ip", "link", "del", customBridge}, false)

	return nil
}
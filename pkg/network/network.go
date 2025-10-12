package network

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var subnets []*net.IPNet
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				subnets = append(subnets, ipnet)
			}
		}
	}

	return subnets, nil
}

func HostInterface(customBridge string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			if iface.Name != customBridge {
				addrs, _ := iface.Addrs()
				if len(addrs) > 0 {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no suitable interface found")
}

func addIptablesRule(table, chain string, args ...string) {
	// Simple fallback to iptables command for now
	// Full netfilter implementation would require complex syscalls
	cmd := []string{"iptables", "-w", "-t", table, "-I", chain, "1"}
	cmd = append(cmd, args...)
	if _, err := command.RunOnHost(cmd, false); err != nil {
		fmt.Printf("Warning: failed to add iptables rule: %v\n", err)
	}
}

func removeIptablesRule(table, chain string, args ...string) {
	cmd := []string{"iptables", "-w", "-t", table, "-D", chain}
	cmd = append(cmd, args...)
	if _, err := command.RunOnHost(cmd, false); err != nil {
		fmt.Printf("Warning: failed to remove iptables rule: %v\n", err)
	}
}

// Netlink wrapper functions - can be replaced with github.com/vishvananda/netlink
func enableIPForwarding() {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		fmt.Printf("Warning: failed to enable IP forwarding: %v\n", err)
	}
}

func createLink(name, linkType string) {
	if _, err := command.RunOnHost([]string{"ip", "link", "add", "name", name, "type", linkType}, false); err != nil {
		fmt.Printf("Warning: failed to create link %s: %v\n", name, err)
	}
}

func setLinkUp(name string) {
	_, _ = command.RunOnHost([]string{"ip", "link", "set", name, "up"}, false)
}

func setLinkDown(name string) {
	_, _ = command.RunOnHost([]string{"ip", "link", "set", name, "down"}, false)
}

func addAddress(iface, addr string) {
	_, _ = command.RunOnHost([]string{"ip", "addr", "add", addr, "dev", iface}, false)
}

func delAddress(iface, addr string) {
	_, _ = command.RunOnHost([]string{"ip", "addr", "del", addr, "dev", iface}, false)
}

func createVethPair(host, guest string) {
	_, _ = command.RunOnHost([]string{"ip", "link", "add", "name", host, "type", "veth", "peer", "name", guest}, false)
}

func setLinkMaster(link, master string) {
	_, _ = command.RunOnHost([]string{"ip", "link", "set", link, "master", master}, false)
}

func setLinkNetns(link string, pid int) {
	_, _ = command.RunOnHost([]string{"ip", "link", "set", link, "netns", strconv.Itoa(pid)}, false)
}

func deleteLink(name string) {
	_, _ = command.RunOnHost([]string{"ip", "link", "del", name}, false)
}

// configureNetworkInContainer uses setns to configure network inside container
func configureNetworkInContainer(containerPID int, vethGuest, containerIP, gatewayIP string) error {
	return command.RunInNamespace(containerPID, syscall.CLONE_NEWNET, func() error {
		_, _ = command.RunOnHost([]string{"ip", "link", "set", "lo", "up"}, false)
		_, _ = command.RunOnHost([]string{"ip", "link", "set", vethGuest, "up"}, false)
		_, _ = command.RunOnHost([]string{"ip", "addr", "add", containerIP, "dev", vethGuest}, false)
		_, _ = command.RunOnHost([]string{"ip", "route", "add", "default", "via", gatewayIP}, false)
		return nil
	})
}

func Create(containerPID int, customBridge, containerRoot, bridgeIP, containerNetwork, containerIP, hostInterface string) error {
	vethHost := fmt.Sprintf("h%d", containerPID)
	vethGuest := fmt.Sprintf("c%d", containerPID)
	gatewayIP := strings.Split(bridgeIP, "/")[0]

	// Enable IP forwarding
	enableIPForwarding()

	// Create bridge
	createLink(customBridge, "bridge")
	setLinkUp(customBridge)
	addAddress(customBridge, bridgeIP)

	// Create VETH pair
	createVethPair(vethHost, vethGuest)
	setLinkMaster(vethHost, customBridge)
	setLinkUp(vethHost)

	// Move VETH to namespace
	setLinkNetns(vethGuest, containerPID)

	// Configure NAT using direct netfilter
	addIptablesRule("nat", "POSTROUTING", "-s", containerNetwork, "-o", hostInterface, "-j", "MASQUERADE")
	addIptablesRule("filter", "FORWARD", "-i", customBridge, "-o", hostInterface, "-j", "ACCEPT")
	addIptablesRule("filter", "FORWARD", "-i", hostInterface, "-o", customBridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	// Write resolv.conf
	resolvPath := filepath.Join(containerRoot, "etc", "resolv.conf")
	if err := os.MkdirAll(filepath.Dir(resolvPath), 0755); err != nil {
		fmt.Printf("Warning: failed to create resolv.conf directory: %v\n", err)
	}
	if err := os.WriteFile(resolvPath, []byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n"), 0644); err != nil {
		fmt.Printf("Warning: failed to write resolv.conf: %v\n", err)
	}

	// Configure network inside container using setns
	if err := configureNetworkInContainer(containerPID, vethGuest, containerIP, gatewayIP); err != nil {
		fmt.Printf("Warning: failed to configure network in container: %v\n", err)
	}

	return nil
}

func Remove(customBridge, bridgeIP, containerNetwork, hostInterface string) error {
	// Remove iptables rules
	removeIptablesRule("nat", "POSTROUTING", "-s", containerNetwork, "-o", hostInterface, "-j", "MASQUERADE")
	removeIptablesRule("filter", "FORWARD", "-i", customBridge, "-o", hostInterface, "-j", "ACCEPT")
	removeIptablesRule("filter", "FORWARD", "-i", hostInterface, "-o", customBridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	// Remove bridge
	delAddress(customBridge, bridgeIP)
	setLinkDown(customBridge)
	deleteLink(customBridge)

	return nil
}

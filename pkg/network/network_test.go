package network

import (
	"strings"
	"testing"
)

func TestGenerateNetworkConfig(t *testing.T) {
	config, err := GenerateNetworkConfig()

	if err != nil {
		t.Fatalf("GenerateNetworkConfig() failed: %v", err)
	}

	if config == nil {
		t.Fatal("config is nil")
	}

	if !strings.Contains(config.ContainerNetwork, "172.") {
		t.Errorf("ContainerNetwork should contain '172.', got: %s", config.ContainerNetwork)
	}

	if !strings.Contains(config.BridgeIP, "172.") {
		t.Errorf("BridgeIP should contain '172.', got: %s", config.BridgeIP)
	}

	if !strings.Contains(config.ContainerIP, "172.") {
		t.Errorf("ContainerIP should contain '172.', got: %s", config.ContainerIP)
	}
}

func TestHostInterface(t *testing.T) {
	iface, err := HostInterface("nonexistent-bridge")

	// Should find some interface (or error if no interfaces)
	if err == nil && iface == "" {
		t.Error("Expected non-empty interface name")
	}
}

func TestGetUsedSubnets(t *testing.T) {
	subnets, err := getUsedSubnets()
	if err != nil {
		t.Errorf("getUsedSubnets() failed: %v", err)
	}
	
	// Should return at least loopback interface
	if len(subnets) == 0 {
		t.Error("Expected at least one subnet")
	}
}

func TestNetworkConfigValidation(t *testing.T) {
	config := &NetworkConfig{
		ContainerNetwork: "172.20.0.0/16",
		BridgeIP:         "172.20.0.1/16",
		ContainerIP:      "172.20.0.2/16",
	}
	
	if !strings.Contains(config.ContainerNetwork, "172.") {
		t.Error("ContainerNetwork should contain 172.")
	}
	if !strings.Contains(config.BridgeIP, "172.") {
		t.Error("BridgeIP should contain 172.")
	}
	if !strings.Contains(config.ContainerIP, "172.") {
		t.Error("ContainerIP should contain 172.")
	}
}

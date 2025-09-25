#!/bin/bash

# Define constant variables
BRIDGE_NAME="mybr0"
CONTAINER_NETWORK="172.19.0.0/16"
BRIDGE_IP="172.19.0.1/16"
HOST_INTERFACE="eno1"

# Make sure the script is running with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run with root privileges."
    exit 1
fi

function create_network() {
    echo "--- Creating network configuration ---"
    
    local CONTAINER_PID=$(pidof unshare)
    if [ -z "$CONTAINER_PID" ]; then
        echo "Error: The 'unshare' process is not running. Start the container first."
        exit 1
    fi
    echo "Container process found (PID: $CONTAINER_PID)."
    
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "IPv4 packet forwarding enabled."
    
    if ip link show $BRIDGE_NAME &> /dev/null; then
        echo "Bridge $BRIDGE_NAME already exists, skipping creation."
    else
        ip link add name $BRIDGE_NAME type bridge
        echo "Bridge $BRIDGE_NAME has been created."
    fi
    
    ip link add name h$CONTAINER_PID type veth peer name c$CONTAINER_PID
    echo "The veth pair (h$CONTAINER_PID i c$CONTAINER_PID) has been created."
    
    ip link set c$CONTAINER_PID netns $CONTAINER_PID
    echo "Interface c$CONTAINER_PID has been moved to the container."

    ip link set h$CONTAINER_PID master $BRIDGE_NAME
    echo "Interfaces h$CONTAINER_PID have been enabled."
    
    ip link set h$CONTAINER_PID up
    ip link set $BRIDGE_NAME up
    echo "Interfaces h$CONTAINER_PID and $BRIDGE_NAME have been enabled."
    
    # Assign an IP address to the bridge
    ip addr add $BRIDGE_IP dev $BRIDGE_NAME
    echo "IP address $BRIDGE_IP assigned to bridge $BRIDGE_NAME."
    
    
    # Configure NAT in iptables
    iptables -t nat -A POSTROUTING -s $CONTAINER_NETWORK -o $HOST_INTERFACE -j MASQUERADE
    echo "NAT rule for $CONTAINER_NETWORK has been added."
    
    # Configure FORWARD rules in iptables
    iptables -I FORWARD -i $BRIDGE_NAME -o $HOST_INTERFACE -j ACCEPT
    iptables -I FORWARD -i $HOST_INTERFACE -o $BRIDGE_NAME -m state --state RELATED,ESTABLISHED -j ACCEPT
    echo "FORWARD rules have been added."
    
    echo "--- Container configuration ---"
    # Enter the container namespace and execute the commands:
    nsenter -t $CONTAINER_PID -n bash -c "
        # Configuring the network inside the container...'
        # Start the container interface
        ip link set c$CONTAINER_PID up
        # Assign an IP address to the container
        ip addr add 172.19.0.2/16 dev c$CONTAINER_PID
        # Set the default gateway
        ip route add default via 172.19.0.1
        # Add DNS servers
        echo 'nameserver 8.8.8.8' > /etc/resolv.conf
        echo 'nameserver 1.1.1.1' >> /etc/resolv.conf
    "
    echo "--- Configuration creation completed ---"
}

function remove_network() {
    echo "--- Starting network configuration cleanup ---"

    local CONTAINER_PID=$(pidof unshare)

    # 1. Removing iptables rules...
    echo "Removing iptables rules..."
    iptables -t nat -D POSTROUTING -s $CONTAINER_NETWORK -o $HOST_INTERFACE -j MASQUERADE 2>/dev/null

    iptables -D FORWARD -i $BRIDGE_NAME -o $HOST_INTERFACE -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i $HOST_INTERFACE -o $BRIDGE_NAME -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null

    echo "Reguły iptables usunięte."

    # 2. Removing the bridge and interfaces...
    echo "Removing the bridge and interfaces..."
    if ip link show $BRIDGE_NAME &> /dev/null; then
        ip link set $BRIDGE_NAME down
        ip link del $BRIDGE_NAME
        echo "Bridge $BRIDGE_NAME has been removed."
    else
        echo "Bridge $BRIDGE_NAME does not exist, skipping deletion."
    fi
        
    # 3. Complete the unshare process
    if [ ! -z "$CONTAINER_PID" ]; then
        echo "Killing container process (PID: $CONTAINER_PID)..."
        kill $CONTAINER_PID
        echo "Container process completed."
    else
        echo "Container process not running, no cleanup."
    fi
    
    echo "--- Cleaning completed ---"
}

# Main part of the script
case "$1" in
    create)
        create_network
        ;;
    remove)
        remove_network
        ;;
    *)
        echo "Usage: $0 {create|remove}"
        exit 1
        ;;
esac
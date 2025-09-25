# Container Creation with Resource Constraints
This bash script, setup_container.sh, serves as an educational example of how to create and run an isolated container on Linux. It uses fundamental Linux tools like unshare, cgroups, chroot, and tar to mimic containerization features without relying on higher-level tools like Docker.

## Understanding the Project: A Simplified Look into Docker's Mechanics
This project is designed to help you understand the core principles behind containerization platforms like Docker. By manually creating a container with basic Linux commands, you'll gain insight into how Docker isolates processes, manages resources, and bundles filesystems. Instead of the "magic" of a single docker run command, you'll see how various components—like cgroups for resource limits and unshare for process isolation—work together to create a contained environment.

## Usage Instructions  
To properly run the container and its network, you must follow the steps below in two separate terminals.

**Terminal 1: Starting the Container**  
Run the container using the setup_container.sh script. This script will create the container's environment and start the main process.
```bash
sudo ./setup_container.sh create
```
After the container starts, the script will display the process PID. At this stage, keep this terminal open as you are entering the container in its namespace.

**Terminal 2: Network Configuration**  
Run the setup_network.sh script to configure the network bridge, virtual interfaces, and iptables rules that will allow the container to access the host's network.
```bash
sudo ./setup_network.sh create
```
This script will automatically detect the running container process and connect it to the network bridge.

**Terminal 1: Testing Connectivity**  
After the network configuration is complete in the second terminal, you can return to the first terminal.

From within the container, which is still open, execute the ping command to check the Internet connection.
```sh
ping 8.8.8.8
```
You should see ping packets being sent and received, which means the container has Internet access.

**Removing Resources**  
To remove the container and all associated resources (files, control groups, network configuration), run the following commands in two separate terminals.

In the terminal where setup_network.sh was run:
```bash
sudo ./setup_network.sh remove
```
In the terminal where setup_container.sh was run:
```bash
sudo ./setup_container.sh remove
```

### How the Script Works:

#### Namespace Isolation (unshare):

**--uts**: Isolates the hostname.  
**--pid**: Creates a new PID namespace, where the main container process has a PID of 1.  
**--net**: Creates a completely isolated network namespace.  
**--mount**: Creates a new mount namespace, preventing changes to the host's filesystem from within the container.  
**--user**: Isolates the user namespace, which maps the container's root user to a non-privileged user on the host.  

#### Resource Limiting (cgroups):

The script creates a new cgroup to limit the container's resources.

**Memory**: 
Limits memory usage to 256MB.

**CPU**: Constrains CPU usage to 50%.

**Filesystem Setup:**

Downloads a minimal Alpine Linux root filesystem.

Extracts it into a directory named my_alpine_root.

Mounts essential virtual filesystems, such as /proc and /sys, within the new namespace.

**Automatic Cleanup:**

Includes functions to automatically clean up the container's root directory and the cgroup after the script finishes, ensuring no leftover files.

#### Prerequisites: ####  
A Linux operating system.

Administrative privileges (sudo).

Required tools: wget, tar, unshare.


**Important Notes:**  
This script is for educational purposes only and should not be used to run sensitive production applications.

While the script provides isolation, it is not as secure or robust as professional solutions like Docker or Podman.

The script assumes the host system uses cgroups version 2.

## Container Network Management Script 
This script provides a complete solution for creating and managing a custom network stack for a container running in a new network namespace (e.g., created with unshare). It automates the configuration of the network bridge, virtual interfaces, and iptables rules, allowing the container to access the internet.

**Features Automated Setup:**  
Creates a virtual network bridge (mybr0), a veth pair, and configures iptables rules for NAT and packet forwarding.

**Container Configuration:**  
Automatically enters the container's network namespace to set up its IP address, default gateway, and DNS servers.

**Easy Cleanup:**  
A dedicated remove function quickly cleans up all created network configurations, including iptables rules, to restore the host system to its original state.

**Troubleshooting Guide:**  
Includes a detailed section for common issues encountered during the setup process.

### Prerequisites
A Linux host with unshare, iproute2, and iptables installed.

The unshare command should be running with a separate network namespace (e.g., sudo unshare --net --fork /bin/bash).

#### Usage
Save the script as setup_network.sh and make it executable:

```Bash
chmod +x setup_network.sh create
```
**1.** Create the Network
First, run your container. The script will automatically detect its PID.

```Bash

sudo unshare --net --fork /bin/bash -c "sleep infinity" &
```
Then, run the script with the create argument:

```Bash
sudo ./setup_network.sh create
```
After the script completes, your container should be able to access the internet. You can enter the container to test it:

```Bash
sudo nsenter -t $(pidof unshare) -n bash
ping google.com
```
**2.** Remove the Network
To remove all network configurations and terminate the container process, run the script with the remove argument:

```Bash
sudo ./setup_network.sh remove
```
### Troubleshooting
If you encounter issues, follow these steps to diagnose the problem. The most common issues are related to iptables rules and DNS.

**1.** No Connectivity from Container to Host
If ping 172.19.0.1 (from inside the container) fails, the problem is between the container and the host.

**Solution:**  
Verify the veth pair and the bridge setup.

On the host, check that the h<PID> interface is up and connected to mybr0: ip addr show h<PID>.

Inside the container, check that the c<PID> interface is up and has the correct IP address: ip addr show c<PID>.

**2.** No Internet Access from the Container
If ping 172.19.0.1 works, but ping 8.8.8.8 fails, the issue is on the host side, preventing traffic from being forwarded to the internet.

**Solution:**  
Verify your iptables rules.

NAT Rule: Check that the MASQUERADE rule includes your host's network interface (eno1). The abbreviated output of iptables -L might not show this.

```Bash
sudo iptables -t nat -L POSTROUTING -v
```
The output should show out eno1 for your 172.19.0.0/16 network. If not, delete the rule and re-add it correctly with the -o flag.

**Forwarding Rules:**  
Check that your ACCEPT rules are placed at the beginning of the FORWARD chain, before the default DROP policy.

```Bash
sudo iptables -t filter -L FORWARD --line-numbers
```

If your ACCEPT rules are at the bottom, they will never be evaluated. Use sudo iptables -I FORWARD to insert them at the top.

**3.** Ping to Domain Names Fails (ping google.com)
If ping 8.8.8.8 works but ping google.com fails, the problem is a lack of DNS configuration inside the container.

**Solution:**  
Manually add nameservers to the container's /etc/resolv.conf file.

Enter the container's namespace:
```
sudo nsenter -t <PID> -n bash.
```

Add nameservers to the file:
```
echo "nameserver 8.8.8.8" > /etc/resolv.conf.
```
Verify the file's content with cat /etc/resolv.conf.

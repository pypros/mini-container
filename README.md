# Container Manager: Educational Linux Containerization

This Python script, `docker.py`, serves as an **educational example** of how to create and manage an isolated Linux container using fundamental OS features and Python's standard libraries. It mimics core containerization features—such as resource limiting, process isolation, and networking—**without relying on higher-level tools like Docker**.

---

## Understanding the Project: Simplified Docker Mechanics

This project is designed to help you understand the **core principles** behind containerization platforms like Docker and Podman.

By manually implementing these features, you gain insight into:
* **Namespace Isolation (`unshare`):** How processes are isolated in their own view of the system (PID, Network, Mount).
* **Resource Limiting (`cgroups`):** How CPU and Memory limits are enforced.
* **Filesystem Layering:** How Docker image layers are downloaded (using the V2 Registry API) and combined to form the final root filesystem.
* **Custom Networking:** How a dedicated network bridge, VETH pair, and NAT rules (`iproute2`, `iptables`) provide container internet access.
  
## Automated Network Configuration Features

The script now **automatically determines and configures** the network settings, eliminating manual IP and interface checks:

* **Non-Conflicting IP Allocation:** Automatically generates a random, private `/16` network (e.g., `172.25.0.0/16`) and checks the host's routing table to **guarantee it doesn't conflict** with existing networks (like Docker bridges or VPNs).
* **Default Interface Detection:** Automatically detects the host's primary network interface (`eno1`, `eth0`, etc.) used for external traffic, ensuring the NAT rule is correctly applied.

---

## Usage Instructions

The script handles all container creation, network setup, and cleanup in a single Python file, simplifying the usage compared to the original two-script setup.

### Prerequisites

* A Linux operating system (assuming `cgroups v2`).
* Administrative privileges (`sudo`).
* Required tools (must be in your system's PATH): **`iproute2`**, **`iptables`**, **`unshare`**, **`tar`**, and **`python3`** with standard libraries.

### 1. Running a Container (`run` command)

The script will download the image, set up cgroups, launch the isolated process, configure the network, and drop you into an interactive shell.

```bash
sudo python3 docker.py run -it alpine:latest
```

 Argument | Description |
| :--- | :--- |
| `run` | Initiates the container creation and launch sequence. |
| `-it` | Runs the container interactively (currently mandatory for this script). |
| `alpine:latest` | The target Docker image (defaults to `alpine:latest`). |

**Inside the Container:**
Once the final message appears (`Entering interactive shell...`), you are inside the container. You can test connectivity:
```sh
ping 8.8.8.8
exit # Type exit to quit the container and trigger cleanup
```

### 2. Removing All Resources (`rm` command)

The cleanup process is automatically run when you exit the container's shell (`exit`). If the script terminates unexpectedly, you can manually run the `rm` command to remove leftover cgroups, network bridges, and files.

```bash
sudo python3 docker.py rm
```
## Core Mechanics: How Isolation is Achieved

### Namespace Isolation (`unshare`)

The main container process is executed using `unshare --kill-child` with the following flags to create the isolated environment:

* `--uts`: Isolates the **hostname**.
* `--pid`: Creates a new **PID namespace**, making the main container process PID 1.
* `--net`: Creates a completely isolated **Network namespace**.
* `--mount`: Creates a new **Mount namespace**, preventing filesystem changes from affecting the host.
* `--user`: Isolates the **User namespace**, mapping the container's root user to a non-privileged user on the host for better security.

### Resource Limiting (`cgroups`)

The script uses `cgroups v2` to set resource constraints on the container process:

* **Memory:** Limited to **256MB**.
* **CPU:** Constrained to **50%** of one CPU core (`50000 100000`).
### Filesystem and Image Download

* **Docker Registry API:** The `download_image` function manually implements the Docker V2 Registry API handshake, token exchange, and layer download (using pure Python's `http.client`).
* **RootFS Assembly:** All downloaded compressed layers are extracted sequentially into the `my_image_root` directory, correctly overlaying the files to form the final, complete root filesystem.

### Network Configuration (Host-side)

All network components are configured on the host using `iproute2` and `iptables` rules based on the container's PID:

| Component | Description |
| :--- | :--- |
| **Bridge** | A virtual bridge (`custbr`) is created with a non-conflicting IP (e.g., `172.25.0.1/16`) acting as the container's gateway. |
| **VETH Pair** | A virtual cable (`h<PID>` <-> `c<PID>`) is created, with one end (`h<PID>`) connected to the bridge and the other end (`c<PID>`) moved into the container's network namespace. |
| **NAT** | **`iptables MASQUERADE`** rules are set up on the host's external interface (`HOST_INTERFACE`) to translate the container's private IP (`172.x.x.x`) to the host's public IP, enabling internet access. |
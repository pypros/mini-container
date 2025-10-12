# Container Manager: Educational Linux Containerization

This Go application serves as an **educational example** of how to create and manage isolated Linux containers using fundamental OS features and Go's syscall package. It demonstrates core containerization principles **without relying on higher-level tools like Docker**.

## Project Evolution

This project has evolved through multiple implementations:

1. **Bash Script** - Initial proof of concept using shell commands
2. **Python Implementation** - More structured approach, but lacked simple syscall access
3. **Go Implementation** - Final version leveraging Go's excellent syscall support and systems programming capabilities

The migration to Go was driven by the need for direct syscall access (`setns`, `mount`, `clone`) without external dependencies, which Python couldn't provide elegantly through its standard library.

---

## Understanding the Project: Simplified Docker Mechanics

This project helps you understand the **core principles** behind containerization platforms like Docker and Podman.

By manually implementing these features, you gain insight into:
* **Namespace Isolation:** How processes are isolated using `clone()` syscalls (PID, Network, Mount, UTS, User)
* **Resource Limiting (`cgroups v2`):** How CPU and Memory limits are enforced
* **Filesystem Layering:** How Docker image layers are downloaded (Docker Registry API v2) and extracted
* **Custom Networking:** How bridge networks, VETH pairs, and NAT rules provide container internet access
* **Direct Syscalls:** How `setns()`, `mount()`, and `sethostname()` work at the kernel level
  
## Key Features

* **Pure Go Implementation** - No external dependencies except CLI library
* **Direct Syscall Usage** - `setns()`, `mount()`, `clone()` without shell commands
* **Automatic Network Configuration** - Conflict-free IP allocation and interface detection
* **Docker Registry Integration** - Downloads real Docker images
* **Comprehensive Testing** - Unit tests and E2E tests

---

## Usage Instructions

### Prerequisites

*   Linux operating system with `cgroups v2`
*   Go 1.21 or later
*   `sudo` privileges for container operations
*   Required system tools: `iproute2`, `iptables`

### Installation

```bash
# Clone and build
git clone <repository>
cd container-manager
go build -o container-manager
```

### Running Containers

**Run with default image (alpine:latest):**
```bash
sudo ./container-manager run
```

**Run with specific image:**
```bash
sudo ./container-manager run --image ubuntu:latest
```

**Get help:**
```bash
./container-manager --help
./container-manager run --help
```

Once inside the container, you can test functionality:
```sh
ping 8.8.8.8    # Test networking
hostname        # Check isolation
ps aux          # See PID namespace
exit            # Quit and cleanup
```

### Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run E2E tests (requires root)
sudo go test -v .
```

### Cleanup

```bash
# Manual cleanup if needed
sudo ./container-manager rm
```

## Core Mechanics: How Isolation is Achieved

### Namespace Isolation (Go Syscalls)

The container process is created using Go's `syscall.SysProcAttr` with `Cloneflags`:

* `CLONE_NEWUTS`: Isolates the **hostname**
* `CLONE_NEWPID`: Creates a new **PID namespace**, making the container process PID 1
* `CLONE_NEWNET`: Creates an isolated **Network namespace**
* `CLONE_NEWNS`: Creates a new **Mount namespace**
* `CLONE_NEWUSER`: Isolates the **User namespace** with UID/GID mapping

### Direct Syscall Usage

The application uses Go's syscall package for low-level operations:

* **`setns()`**: Enter existing namespaces for configuration
* **`mount()`**: Mount `/proc`, `/sys`, and `/dev` filesystems
* **`sethostname()`**: Set container hostname
* **Custom syscall wrapper**: `SYS_SETNS = 308` for x86_64 Linux

### Resource Limiting (cgroups v2)

Resource constraints are applied using cgroups v2:

* **Memory**: Limited to **256MB** (`memory.max`)
* **CPU**: Constrained to **50%** of one CPU core (`cpu.max = 50000 100000`)

### Image Management

* **Docker Registry API v2**: Pure Go HTTP client implementation
* **Layer Download**: Automatic manifest parsing and blob downloading
* **Filesystem Assembly**: Sequential layer extraction to build container root

### Network Configuration

Network setup using Go's `net` package and system commands:

| Component | Implementation |
| :--- | :--- |
| **Bridge Creation** | `ip link add` with conflict-free IP allocation |
| **VETH Pair** | Virtual ethernet pair (`h<PID>` <-> `c<PID>`) |
| **Namespace Assignment** | `ip link set netns` to move interface |
| **NAT Rules** | `iptables MASQUERADE` for internet access |
| **Configuration** | `setns()` syscall to configure inside container |

## Architecture

```
cmd/
├── main.go              # CLI and container orchestration
pkg/
├── api/                 # Docker Registry API client
├── command/             # Syscall wrappers and utilities
├── downloader/          # Image download and extraction
└── network/             # Network configuration
```

## Dependencies

- **github.com/urfave/cli/v2** (MIT License) - CLI framework
- **Go standard library** - All core functionality

## License

This project demonstrates educational containerization concepts and is provided under the MIT License.
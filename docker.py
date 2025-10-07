import subprocess
import os
import signal
import time
import sys
import shutil
from typing import List, Optional
from pathlib import Path
import argparse
import re
import logging
import ipaddress
import random
import image_downloader


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def run_cmd_host(
    cmd: List[str],
    pipe_output: bool = False,
    input_data: Optional[str] = None,
    check_error: bool = True,
    ignore_stderr: bool = False,
) -> Optional[str]:
    """Helper function to execute shell commands using subprocess."""
    try:
        if input_data:
            # If input_data is provided, it's passed via stdin
            input_data = (input_data.encode("utf-8"),)
        process = subprocess.run(
            cmd,
            input=input_data,
            capture_output=pipe_output,
            check=check_error,
            text=True,
            stderr=subprocess.DEVNULL if ignore_stderr else None,
        )
        if pipe_output and process.stdout:
            return process.stdout.strip()
        return None
    except subprocess.CalledProcessError as e:
        if check_error:
            logger.error(f"Error executing command: {' '.join(cmd)}")
            logger.error(f"Return code: {e.returncode}")
            sys.exit(e.returncode)
        return None
    except FileNotFoundError:
        logger.error(f"Error: Command not found: {cmd}")
        sys.exit(1)


def run_cmd_on_container(
    container_pid: int, cmd: str, container_root: Path
) -> Optional[str]:
    """
    Executes a shell command or a multi-command string inside the container's
    isolated namespaces (mount, net, uts) using nsenter.

    Args:
        container_pid (int): The PID of the container's main process (PID 1).
        cmd (str): The shell command string to execute (e.g., 'ip addr show').

    Returns:
        Optional[str]: The command output if piped, otherwise None.
    """
    # Build the nsenter command. The actual command string is passed
    # to /bin/sh -c to allow multiple commands or complex strings to run.
    nsenter_cmd = [
        "nsenter",
        "-t",
        str(container_pid),
        "--mount",
        "--net",
        "--uts",
        f"--root={container_root}",
        "/bin/sh",
        "-c",
        cmd,  # Pass the command string as the argument to /bin/sh -c
    ]

    # Call the original run_cmd function. We set pipe_output=True for maximum
    # utility, although network setup might not need it.
    return run_cmd_host(nsenter_cmd, pipe_output=True, check_error=True)


class NetworkGenerationError(RuntimeError):
    """Raised when a free subnet cannot be found after the maximum number of attempts."""

    pass


def get_used_subnets():
    """Retrieves a list of all subnets used on the host based on the routing table."""
    used_subnets = set()
    # Show all routes in CIDR format
    route_output = run_cmd_host(
        ["ip", "route", "show"], pipe_output=True, check_error=False
    )

    if not route_output:
        return used_subnets

    for line in route_output.splitlines():
        # We are interested in entries starting with an IP address (usually containing a mask)
        # Examples: 192.168.1.0/24, 10.0.0.0/8, 172.16.0.0/16

        # Search for an address in A.B.C.D/Mask format
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", line)

        if match:
            try:
                # Add the network to the set to avoid duplicates
                # ipaddress automatically normalizes the format (e.g., 192.168.1.5/24 -> 192.168.1.0/24)
                network = ipaddress.ip_network(match.group(1), strict=False)
                used_subnets.add(network)
            except ValueError:
                # Ignore invalid IP formats
                continue
    return used_subnets


def generate_non_conflicting_network_config():
    """
    Generates a unique set of IP addresses that does not conflict with active host networks.
    Picks a random, private /16 subnet from the 172.16.0.0/12 range.
    """

    used_subnets = get_used_subnets()
    MAX_TRIES = 5

    # Private Class B range is 172.16.0.0/12, spanning 172.16.x.x to 172.31.x.x
    for _ in range(MAX_TRIES):
        # 1. Randomly select the second octet (16 to 31)
        random_second_octet = random.randint(16, 31)
        network_base = f"172.{random_second_octet}.0.0/16"

        try:
            new_net = ipaddress.ip_network(network_base)
        except ValueError:
            # Skip if the address is invalid for some reason
            continue

        # 2. Check for conflict
        is_conflicting = False
        for used_net in used_subnets:
            # Check if the new network (new_net) overlaps with any existing one
            if new_net.overlaps(used_net):
                # logger.warning(f"Randomly selected network {new_net} conflicts with {used_net}. Retrying...")
                is_conflicting = True
                break

        # If no conflict, return the configuration
        if not is_conflicting:
            # 3. Assign addresses
            # Bridge IP (Gateway) - The first usable address
            bridge_ip_full = ipaddress.IPv4Address(int(new_net.network_address) + 1)
            # Container IP - The second usable address
            container_ip_full = ipaddress.IPv4Address(int(new_net.network_address) + 2)

            return {
                "container_network": str(new_net),
                "bridge_ip": f"{bridge_ip_full}/{new_net.prefixlen}",
                "container_ip": f"{container_ip_full}/{new_net.prefixlen}",
            }
    raise NetworkGenerationError(
        f"Can't to find a free /16 subnet in the 172.16.0.0/12 range after {MAX_TRIES} attempts. "
        "Check the active network configuration (e.g., Docker, VPN, bridges) on the host."
    )


def find_host_interface(custom_bridge: str):
    route_output = run_cmd_host(
        ["ip", "route", "show", "default"], pipe_output=True, check_error=True
    )
    match = re.search(r"dev\s+(\S+)", route_output)
    if match:
        interface_name = match.group(1)
        logger.info(f"Found default interface: {interface_name}")
        if interface_name not in ("lo", custom_bridge):
            return interface_name


def get_arch() -> str:
    """Determines system architecture for Docker manifest using a dictionary lookup."""
    ARCHITECTURE_MAP = {
        "x86_64": "amd64",
        "aarch64": "arm64",
        "arm": "arm",
        "armv7l": "arm",
    }
    uname_arch = run_cmd_host(["uname", "-m"], pipe_output=True)
    docker_arch = ARCHITECTURE_MAP.get(uname_arch, "amd64")
    if docker_arch == "amd64" and uname_arch not in ARCHITECTURE_MAP:
        logger.warning(
            f"Unknown system architecture ({uname_arch}). Using default: amd64."
        )
    return docker_arch


def parse_image(full_image_arg):
    if ":" not in full_image_arg:
        image_name = full_image_arg
        tag = "latest"
    else:
        image_name, tag = full_image_arg.split(":", 1)

    if "/" not in image_name:
        name = f"library/{image_name}"
    else:
        name = image_name

    return name, tag


def setup_network(
    container_pid: int,
    custom_bridge: str,
    container_root: str,
    bridge_ip: str,
    container_network: str,
):
    """Creates VETH, bridge, NAT, and configures the network using the container's PID.

    This function is optimized to reduce the number of external program calls to 8.
    """
    logger.info("--- CONFIGURING NETWORK (Host) ---")

    veth_host = f"h{container_pid}"
    veth_guest = f"c{container_pid}"
    gateway_ip = bridge_ip.split("/")[0]

    logger.info("1/8: Enabling IP Forwarding...")
    IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"
    run_cmd_host(["echo", "1", ">", IP_FORWARD_PATH])

    logger.info("2/8: Creating Bridge and assigning IP...")
    run_cmd_host(
        ["ip", "link", "add", "name", custom_bridge, "type", "bridge"],
        ignore_stderr=True,
        check_error=False,
    )
    run_cmd_host(["ip", "link", "set", custom_bridge, "up"])
    run_cmd_host(
        ["ip", "addr", "add", bridge_ip, "dev", custom_bridge],
        check_error=False,
        ignore_stderr=True,
    )

    logger.info("3/8: Creating VETH pair...")
    run_cmd_host(
        [
            "ip",
            "link",
            "add",
            "name",
            veth_host,
            "type",
            "veth",
            "peer",
            "name",
            veth_guest,
        ]
    )
    run_cmd_host(["ip", "link", "set", veth_host, "master", custom_bridge])
    run_cmd_host(["ip", "link", "set", veth_host, "up"])

    logger.info("4/8: Moving VETH to namespace...")
    run_cmd_host(["ip", "link", "set", veth_guest, "netns", str(container_pid)])

    logger.info("5/8: Configuring NAT (iptables)...")
    run_cmd_host(
        [
            "iptables",
            "-w",
            "-t",
            "nat",
            "-I",
            "POSTROUTING",
            "1",
            "-s",
            container_network,
            "-o",
            host_interface,
            "-j",
            "MASQUERADE",
        ]
    )
    run_cmd_host(
        [
            "iptables",
            "-w",
            "-I",
            "FORWARD",
            "1",
            "-i",
            custom_bridge,
            "-o",
            host_interface,
            "-j",
            "ACCEPT",
        ]
    )
    run_cmd_host(
        [
            "iptables",
            "-w",
            "-I",
            "FORWARD",
            "1",
            "-i",
            host_interface,
            "-o",
            custom_bridge,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ]
    )

    logger.info("6/8: Writing resolv.conf...")
    try:
        RESOLV_CONF_PATH = os.path.join(container_root, "etc", "resolv.conf")
        os.makedirs(os.path.join(container_root, "etc"), exist_ok=True)
        with open(RESOLV_CONF_PATH, "w") as f:
            f.write("nameserver 8.8.8.8\n" "nameserver 1.1.1.1\n")
    except Exception as e:
        logger.error(f"Error writing resolv.conf: {e}")
        sys.exit(1)

    logger.info("7/8: Configuring network inside container...")
    run_cmd_on_container(
        container_pid,
        f"""
            ip link set lo up && \
            ip link set {veth_guest} up && \
            ip addr add {container_ip} dev {veth_guest} && \
            ip route add default via {gateway_ip};
        """,
        container_root,
    )

    logger.info("--- NETWORK CONFIGURATION COMPLETE ---")


def remove_network_config(
    custom_bridge: str,
    container_network: str,
    host_interface: str,
):
    """Removes global network configurations (iptables, bridge)."""
    logger.info("--- CLEANING GLOBAL NETWORK CONFIGURATION ---")

    logger.info("1. Removing iptables rules...")
    run_cmd_host(
        [
            "iptables",
            "-w",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            container_network,
            "-o",
            host_interface,
            "-j",
            "MASQUERADE",
        ],
        check_error=False,
        ignore_stderr=True,
    )
    run_cmd_host(
        [
            "iptables",
            "-w",
            "-D",
            "FORWARD",
            "-i",
            custom_bridge,
            "-o",
            host_interface,
            "-j",
            "ACCEPT",
        ],
        check_error=False,
        ignore_stderr=True,
    )
    run_cmd_host(
        [
            "iptables",
            "-w",
            "-D",
            "FORWARD",
            "-i",
            host_interface,
            "-o",
            custom_bridge,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        check_error=False,
        ignore_stderr=True,
    )

    logger.info("Iptables rules removed.")

    if run_cmd_host(
        ["ip", "link", "show", custom_bridge], check_error=False, pipe_output=True
    ):
        logger.info(f"2. Removing bridge {custom_bridge}...")
        run_cmd_host(
            ["ip", "addr", "del", bridge_ip, "dev", custom_bridge],
            check_error=False,
            ignore_stderr=True,
        )
        run_cmd_host(
            ["ip", "link", "set", custom_bridge, "down"],
            check_error=False,
            ignore_stderr=True,
        )
        run_cmd_host(
            ["ip", "link", "del", custom_bridge], check_error=False, ignore_stderr=True
        )
        logger.info("Bridge removed.")
    else:
        logger.info("INFO: Bridge does not exist, skipping deletion.")
    logger.info("--- GLOBAL NETWORK CLEANUP COMPLETE ---")


def cleanup_container(
    container_pid: int, image_arg: str, container_root: Path, cgrup_path: Path
):
    """Cleans up container artifacts (process, VETH, cgroups, rootfs)."""
    logger.info("--- CLEANING CONTAINER ARTIFACTS ---")

    # 1. Stop the unshare process
    if container_pid > 0:
        try:
            os.kill(container_pid, signal.SIGKILL)
            logger.info(f"1. Terminated container process (PID: {container_pid}).")
        except ProcessLookupError:
            pass

    logger.info("2. Removing lingering host VETH interfaces...")
    veth_list_raw = run_cmd_host(
        ["ip", "link", "show"], pipe_output=True, check_error=False
    )
    if veth_list_raw:
        # Search for lines starting with h[digit]@
        veth_matches = re.findall(r"(\bh\d+@if\d+):", veth_list_raw)
        for veth_match in veth_matches:
            iface_name = veth_match.split("@")[0]
            run_cmd_host(
                ["ip", "link", "del", iface_name], check_error=False, ignore_stderr=True
            )
    logger.info("VETH interfaces checked/removed.")

    logger.info(f"3. Removing container root filesystem: {container_root}")
    run_cmd_host(
        ["umount", f"{container_root}/dev"], check_error=False, ignore_stderr=True
    )
    run_cmd_host(
        ["umount", f"{container_root}/proc"], check_error=False, ignore_stderr=True
    )
    run_cmd_host(
        ["umount", f"{container_root}/sys"], check_error=False, ignore_stderr=True
    )

    shutil.rmtree(container_root, ignore_errors=True)
    logger.info("Root filesystem removed.")

    logger.info("4. Remove cgroup director...")
    shutil.rmtree(cgrup_path, ignore_errors=True)

    logger.info("5. Removing temporary build artifacts...")
    shutil.rmtree(BUILD_TEMP_DIR, ignore_errors=True)
    shutil.rmtree(IMAGE_LAYERS_DIR, ignore_errors=True)
    shutil.rmtree(COMPOSE_DIR, ignore_errors=True)

    logger.info("6. Clean up the .tar file")
    image_to_cleanup = image_arg if image_arg else "alpine:latest"
    input_image, tag = (
        image_to_cleanup.split(":", 1)
        if ":" in image_to_cleanup
        else (image_to_cleanup, "latest")
    )
    final_tar_name = Path(
        f"{input_image.replace('/', '_')}_{tag.replace(':', '_')}_loaded.tar"
    )
    final_tar_name.unlink(missing_ok=True)

    logger.info("Build artifacts removed.")

    logger.info("--- CONTAINER ARTIFACTS CLEANUP COMPLETE ---")


def main_create(
    image_arg: str, container_root: Path, cgrup_path: Path
):
    """Main function to create and run the container with PID 1 as /bin/sh."""

    # 1. Download and prepare the filesystem (MANUAL DOWNLOAD)
    image, tag = parse_image(image_arg)
    architecture = get_arch()
    image_downloader.download_image(
        image_arg,
        image,
        tag,
        architecture,
        BUILD_TEMP_DIR,
        IMAGE_LAYERS_DIR,
        container_root,
        COMPOSE_DIR,
    )

    logger.info("\n2. Configuring cgroups and mounting /dev...")
    # Attempt to mount cgroup2, ignoring errors if already mounted
    run_cmd_host(
        ["mount", "-t", "cgroup2", "none", "/sys/fs/cgroup"],
        check_error=False,
        ignore_stderr=True,
    )
    cgrup_path.mkdir(parents=True, exist_ok=True)
    memory_path = cgrup_path / "memory.max"
    try:
        with open(memory_path, "w") as f:
            f.write("256M")
        logger.info(f"Memory limit set to 256MB in {memory_path.name}")
    except OSError as e:
        logger.error(
            f"Failed to set memory limit: {e.strerror}. (Required permissions?)"
        )

    # 2. Writing CPU limit (instead of 'echo 50000 100000 > ...')
    cpu_path = cgrup_path / "cpu.max"
    try:
        with open(cpu_path, "w") as f:
            f.write("50000 100000")
        logger.info(f"CPU limit set to 50% in {cpu_path.name}")
    except OSError as e:
        logger.error(f"Failed to set CPU limit: {e.strerror}. (Required permissions?)")

    run_cmd_host(["mount", "-t", "devtmpfs", "none", f"{container_root}/dev"])
    logger.info("Cgroups configured.")

    # 3. Launch the container process (Init Script)
    logger.info("\n3. Launching Init Script (PID 1) in the isolated environment...")

    # Handshake File - used to signal that the network is ready
    NETWORK_READY_FLAG = "network_ready"

    # Script executed as PID 1 in the container
    CONTAINER_INIT_CMD = f"""
        # 1. Mount essential filesystems
        mount -t proc proc /proc;
        mount -t sysfs sys /sys;
        hostname "my-pid1-container";

        # 2. Wait for Host to configure network (Handshake)
        echo "PID 1 (Init Script) waiting for network configuration from Host...";
        while [ ! -f /{NETWORK_READY_FLAG} ]; do sleep 0.1; done;

        # 3. Clean up the flag
        rm -f /{NETWORK_READY_FLAG};

        # 4. Final step: Replace this process with the target shell
        # Set up basic environment variables
        export HOME=/root
        export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
        export TERM=xterm
        
        # 5. Execute the shell
        exec /bin/sh -i;
    """

    unshare_cmd = [
        "unshare",
        "--uts",
        "--pid",
        "--net",
        "--mount",
        "--user",
        "--kill-child",
        "--map-root-user",
        f"--root={container_root}",
        "/bin/sh",
        "-c",
        CONTAINER_INIT_CMD,
    ]

    # Run in Popen mode to allow the process to be immediately accessible and to connect the terminal
    unshare_proc = subprocess.Popen(
        unshare_cmd, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr
    )
    unshare_pid = unshare_proc.pid

    logger.info(
        f"Unshare Host PID captured: {unshare_pid}. This process will become /bin/sh (PID 1)."
    )
    time.sleep(1)  # Give time for startup and /proc mounting

    # Assign PID to Cgroup on the HOST
    run_cmd_host(["sh", "-c", f"echo {unshare_pid} > {cgrup_path}/cgroup.procs"])

    try:
        setup_network(
            unshare_pid,
            custom_bridge,
            container_root,
            bridge_ip,
            container_network,
        )

        logger.info("\n4. Network ready. Sending Handshake signal to PID 1...")
        run_cmd_host(
            ["rm", "-f", f"{container_root}/{NETWORK_READY_FLAG}"],
            check_error=False,
            ignore_stderr=True,
        )
        run_cmd_host(["touch", f"{container_root}/{NETWORK_READY_FLAG}"])

        logger.info(
            "\n5. Entering interactive shell (PID 1 is now /bin/sh. Type 'exit' to quit)..."
        )
        unshare_proc.wait()

        logger.info("\nShell exited.")

    except Exception as e:
        logger.critical(f"\nDuring configuration or runtime: {e}")
        try:
            os.kill(unshare_pid, signal.SIGKILL)
        except:
            pass
    finally:
        logger.info("\n6. Initiating cleanup...")
        remove_network_config(custom_bridge, container_network, host_interface)
        cleanup_container(unshare_pid, image_arg, container_root, cgrup_path)
        logger.info("Container management process finished.")


def get_parent_pid_of_shell():
    unshare_pid = 0
    pid_list_raw = run_cmd_host(
        ["pgrep", "-f", "/bin/sh -i"], pipe_output=True, check_error=False
    )
    if pid_list_raw:
        init_pid = pid_list_raw.split()[0]
        unshare_pid_raw = run_cmd_host(
            ["ps", "-o", "ppid=", "-p", init_pid], pipe_output=True, check_error=False
        )
        if unshare_pid_raw:
            unshare_pid = int(unshare_pid_raw.strip())
        else:
            unshare_pid = 0
    return unshare_pid


def main_remove(
    image_arg: str,
    container_root: Path,
    custom_bridge: str,
    host_interface: str,
    cgrup_path: Path,
):
    """Main function to remove all resources."""
    unshare_pid = get_parent_pid_of_shell()
    remove_network_config(custom_bridge, container_network, host_interface)
    cleanup_container(unshare_pid, image_arg, container_root, cgrup_path)
    logger.info("Full resource cleanup complete.")


def parse_args():
    """
    Parses command-line arguments using argparse for 'run' and 'rm' actions.
    """
    parser = argparse.ArgumentParser(
        description="A simple container manager.",
        epilog="Example usage: sudo python3 container_manager.py run -it ubuntu:latest",
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="The container action to perform."
    )

    run_parser = subparsers.add_parser("run", help="Run a command in a new container.")

    # Adding the '-it' flags (which are currently implied by main_create)
    # We add them here for compatibility, but don't need to check their value since the script always runs interactively.
    run_parser.add_argument(
        "-it",
        action="store_true",
        help="Run container interactively (currently mandatory, included for Docker compatibility).",
    )

    run_parser.add_argument(
        "image_arg",
        nargs="?",
        default="alpine:latest",
        help="The image name and tag (e.g., alpine:latest). Defaults to alpine:latest.",
    )

    rm_parser = subparsers.add_parser(
        "rm", help="Remove all global and container-specific resources."
    )
    rm_parser.add_argument(
        "image_arg",
        nargs="?",
        default="alpine:latest",
        help="The image name used during creation (for cleaning up the .tar file). Defaults to alpine:latest.",
    )

    return parser.parse_args()


if __name__ == "__main__":
    container_root = Path("./my_image_root")
    custom_bridge = "custom-bridge-0"
    host_interface = find_host_interface(custom_bridge)
    logger.info(f"Using host interface: {host_interface}")

    # Cgroups
    CGROUP_NAME = Path("my_custom_container")
    CGROUP_PATH = Path("/sys/fs/cgroup") / CGROUP_NAME

    # Directories created during image download (NEW)
    BUILD_TEMP_DIR = Path(".docker_temp")
    COMPOSE_DIR = BUILD_TEMP_DIR / "compose_temp"
    IMAGE_LAYERS_DIR = Path(".image_layers")


    config = generate_non_conflicting_network_config()

    container_network = config["container_network"]
    bridge_ip = config["bridge_ip"]
    container_ip = config["container_ip"]

    args = parse_args()

    if args.command == "run":
        main_create(args.image_arg, container_root, CGROUP_PATH)
    elif args.command == "rm":
        main_remove(
            args.image_arg, container_root, custom_bridge, host_interface, CGROUP_PATH
        )

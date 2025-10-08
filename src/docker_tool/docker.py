import argparse
import contextlib
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import command, image_downloader, network

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def get_arch() -> str:
    """Determines system architecture for Docker manifest using a dictionary lookup."""
    architectures = {
        "x86_64": "amd64",
        "aarch64": "arm64",
        "arm": "arm",
        "armv7l": "arm",
    }
    uname_arch = command.run_on_host(["uname", "-m"], pipe_output=True)
    docker_arch = architectures.get(uname_arch or "", "amd64")
    if docker_arch == "amd64" and uname_arch not in architectures:
        logger.warning(
            f"Unknown system architecture ({uname_arch}). Using default: amd64."
        )
    return docker_arch


def parse_image(full_image_arg: str) -> tuple[str, str]:
    if ":" not in full_image_arg:
        image_name = full_image_arg
        tag = "latest"
    else:
        image_name, tag = full_image_arg.split(":", 1)

    name = f"library/{image_name}" if "/" not in image_name else image_name

    return name, tag


def cleanup_container(
    container_pid: int,
    image_arg: str,
    container_root: Path,
    control_groups: Path,
    build_temp_dir: Path,
    image_layers_dir: Path,
    compose_dir: Path,
) -> None:
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
    veth_list_raw = command.run_on_host(
        ["ip", "link", "show"], pipe_output=True, check_error=False
    )
    if veth_list_raw:
        # Search for lines starting with h[digit]@
        veth_matches = re.findall(r"(\bh\d+@if\d+):", veth_list_raw)
        for veth_match in veth_matches:
            iface_name = veth_match.split("@")[0]
            command.run_on_host(
                ["ip", "link", "del", iface_name], check_error=False, ignore_stderr=True
            )
    logger.info("VETH interfaces checked/removed.")

    logger.info(f"3. Removing container root filesystem: {container_root}")

    command.run_on_host(
        ["umount", f"{container_root}/dev"], check_error=False, ignore_stderr=True
    )
    command.run_on_host(
        ["umount", f"{container_root}/proc"], check_error=False, ignore_stderr=True
    )
    command.run_on_host(
        ["umount", f"{container_root}/sys"], check_error=False, ignore_stderr=True
    )

    shutil.rmtree(container_root, ignore_errors=True)
    logger.info("Root filesystem removed.")

    logger.info("4. Remove cgroup director...")
    shutil.rmtree(control_groups, ignore_errors=True)

    logger.info("5. Removing temporary build artifacts...")
    shutil.rmtree(build_temp_dir, ignore_errors=True)
    shutil.rmtree(image_layers_dir, ignore_errors=True)
    shutil.rmtree(compose_dir, ignore_errors=True)

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


def create(
    image_arg: str,
    container_root: Path,
    control_groups: Path,
    build_temp_dir: Path,
    image_layers_dir: Path,
    compose_dir: Path,
) -> None:
    """Main function to create and run the container with PID 1 as /bin/sh."""

    # 1. Download and prepare the filesystem (MANUAL DOWNLOAD)
    image, tag = parse_image(image_arg)
    architecture = get_arch()
    image_downloader.download_image(
        image_arg,
        image,
        tag,
        architecture,
        build_temp_dir,
        image_layers_dir,
        container_root,
        compose_dir,
    )

    logger.info("2. Configuring cgroups and mounting /dev...")
    # Attempt to mount cgroup2, ignoring errors if already mounted
    command.run_on_host(
        ["mount", "-t", "cgroup2", "none", "/sys/fs/cgroup"],
        check_error=False,
        ignore_stderr=True,
    )
    control_groups.mkdir(parents=True, exist_ok=True)
    memory_path = control_groups / "memory.max"
    try:
        with open(memory_path, "w") as f:
            f.write("256M")
        logger.info(f"Memory limit set to 256MB in {memory_path.name}")
    except OSError as e:
        logger.error(
            f"Failed to set memory limit: {e.strerror}. (Required permissions?)"
        )

    # 2. Writing CPU limit (instead of 'echo 50000 100000 > ...')
    cpu_path = control_groups / "cpu.max"
    try:
        with open(cpu_path, "w") as f:
            f.write("50000 100000")
        logger.info(f"CPU limit set to 50% in {cpu_path.name}")
    except OSError as e:
        logger.error(f"Failed to set CPU limit: {e.strerror}. (Required permissions?)")

    command.run_on_host(["mount", "-t", "devtmpfs", "none", f"{container_root}/dev"])
    logger.info("Cgroups configured.")

    # 3. Launch the container process (Init Script)
    logger.info("3. Launching Init Script (PID 1) in the isolated environment...")

    # Handshake File - used to signal that the network is ready
    network_ready_flag = "network_ready"

    # Script executed as PID 1 in the container
    container_init_cmd = f"""
        # 1. Mount essential filesystems
        mount -t proc proc /proc;
        mount -t sysfs sys /sys;
        hostname "my-pid1-container";

        # 2. Wait for Host to configure network (Handshake)
        echo "PID 1 (Init Script) waiting for network configuration from Host...";
        while [ ! -f /{network_ready_flag} ]; do sleep 0.1; done;

        # 3. Clean up the flag
        rm -f /{network_ready_flag};

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
        container_init_cmd,
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
    command.run_on_host(
        ["sh", "-c", f"echo {unshare_pid} > {control_groups}/cgroup.procs"]
    )

    try:
        network.create(
            unshare_pid,
            custom_bridge,
            str(container_root),
            bridge_ip,
            container_network,
            container_ip,
            host_interface or "",
        )

        logger.info("4. Network ready. Sending Handshake signal to PID 1...")
        command.run_on_host(
            ["rm", "-f", f"{container_root}/{network_ready_flag}"],
            check_error=False,
            ignore_stderr=True,
        )
        command.run_on_host(["touch", f"{container_root}/{network_ready_flag}"])

        logger.info(
            "5. Entering interactive shell (PID 1 is now /bin/sh. Type 'exit' to quit)..."
        )
        unshare_proc.wait()

        logger.info("Shell exited.")

    except Exception as e:
        logger.critical(f"During configuration or runtime: {e}")
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(os.getpgid(unshare_pid), signal.SIGTERM)

    finally:
        logger.info("6. Initiating cleanup...")
        network.remove(
            custom_bridge, bridge_ip, container_network, host_interface or ""
        )
        cleanup_container(
            unshare_pid,
            image_arg,
            container_root,
            control_groups,
            build_temp_dir,
            image_layers_dir,
            compose_dir,
        )
        logger.info("Container management process finished.")


def get_parent_pid_of_shell() -> int:
    unshare_pid = 0
    pid_list_raw = command.run_on_host(
        ["pgrep", "-f", "/bin/sh -i"], pipe_output=True, check_error=False
    )
    if pid_list_raw:
        init_pid = pid_list_raw.split()[0]
        unshare_pid_raw = command.run_on_host(
            ["ps", "-o", "ppid=", "-p", init_pid], pipe_output=True, check_error=False
        )
        unshare_pid = int(unshare_pid_raw.strip()) if unshare_pid_raw else 0
    return unshare_pid


def remove(
    image_arg: str,
    container_root: Path,
    custom_bridge: str,
    bridge_ip: str,
    container_network: str,
    host_interface: str | None,
    control_groups: Path,
) -> None:
    """Main function to remove all resources."""
    unshare_pid = get_parent_pid_of_shell()
    network.remove(custom_bridge, bridge_ip, container_network, host_interface or "")
    cleanup_container(
        unshare_pid,
        image_arg,
        container_root,
        control_groups,
        build_temp_dir,
        image_layers_dir,
        compose_dir,
    )
    logger.info("Full resource cleanup complete.")


def parse_args() -> argparse.Namespace:
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
    host_interface = network.host_interface(custom_bridge)
    logger.info(f"Using host interface: {host_interface}")

    control_groups = Path("/sys/fs/cgroup") / "my_custom_container"

    # Directories created during image download (NEW)
    build_temp_dir = Path(".docker_temp")
    compose_dir = build_temp_dir / "compose_temp"
    image_layers_dir = build_temp_dir / "image_layers"

    config = network.generate_network_config()

    container_network = config["container_network"]
    bridge_ip = config["bridge_ip"]
    container_ip = config["container_ip"]

    args = parse_args()

    if args.command == "run":
        create(
            args.image_arg,
            container_root,
            control_groups,
            build_temp_dir,
            image_layers_dir,
            compose_dir,
        )
    elif args.command == "rm":
        remove(
            args.image_arg,
            container_root,
            custom_bridge,
            bridge_ip,
            container_network,
            host_interface,
            control_groups,
        )

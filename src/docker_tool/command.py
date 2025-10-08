import subprocess
import sys
from typing import List, Optional
from pathlib import Path
import logging


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def run_on_host(
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


def run_on_container(
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
    return run_on_host(nsenter_cmd, pipe_output=True, check_error=True)

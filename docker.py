import subprocess
import os
import signal
import time
import sys
import shutil
import json
from typing import List, Optional
from pathlib import Path
import http.client
import urllib.parse
import tarfile
import ssl
import argparse
import re
import logging
import ipaddress
import random


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


def run_cmd_on_container(container_pid: int, cmd: str) -> Optional[str]:
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
        f"--root={CONTAINER_ROOT}",
        "/bin/sh",
        "-c",
        cmd,  # Pass the command string as the argument to /bin/sh -c
    ]

    # Call the original run_cmd function. We set pipe_output=True for maximum
    # utility, although network setup might not need it.
    return run_cmd_host(nsenter_cmd, pipe_output=True, check_error=True)


# --- GLOBAL CONFIGURATION ---
CONTAINER_ROOT = Path("./my_image_root")
# Network Configuration
BRIDGE_NAME = "custom-bridge-0"


class NetworkGenerationError(RuntimeError):
    """Raised when a free subnet cannot be found after the maximum number of attempts."""

    pass


def get_used_subnets(run_cmd_host_func):
    """Retrieves a list of all subnets used on the host based on the routing table."""
    used_subnets = set()
    # Show all routes in CIDR format
    route_output = run_cmd_host_func(
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


def generate_non_conflicting_network_config(run_cmd_host_func):
    """
    Generates a unique set of IP addresses that does not conflict with active host networks.
    Picks a random, private /16 subnet from the 172.16.0.0/12 range.
    """

    used_subnets = get_used_subnets(run_cmd_host_func)
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


config = generate_non_conflicting_network_config(run_cmd_host)

container_network = config["container_network"]
bridge_ip = config["bridge_ip"]
container_ip = config["container_ip"]


def find_host_interface():
    route_output = run_cmd_host(
        ["ip", "route", "show", "default"], pipe_output=True, check_error=True
    )
    match = re.search(r"dev\s+(\S+)", route_output)
    if match:
        interface_name = match.group(1)
        logger.info(f"Found default interface: {interface_name}")
        if interface_name not in ("lo", BRIDGE_NAME):
            return interface_name


host_interface = find_host_interface()
logger.info(f"Using host interface: {host_interface}")

# Cgroups
CGROUP_NAME = Path("my_custom_container")
CGROUP_PATH = Path("/sys/fs/cgroup") / CGROUP_NAME

# Handshake File - used to signal that the network is ready
NETWORK_READY_FLAG = "network_ready"

# Directories created during image download (NEW)
BUILD_TEMP_DIR = Path(".docker_temp")
IMAGE_LAYERS_DIR = Path(".image_layers")
COMPOSE_DIR = os.path.join(BUILD_TEMP_DIR, "compose_temp")  # Will use temp/compose_temp


def cleanup_download_artifacts():
    """Removes temporary directories after image download and extraction."""
    for directory in [CONTAINER_ROOT, BUILD_TEMP_DIR, IMAGE_LAYERS_DIR, COMPOSE_DIR]:
        if os.path.isdir(directory):
            try:
                shutil.rmtree(directory)
            except OSError as e:
                logger.error(
                    f"Error cleaning download artifacts {directory}: {e}"
                )  # Błąd czyszczenia artefaktów pobierania


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


def request(host, url, method="GET", headers={}, save_path=None):
    """
    General function for performing HTTP/HTTPS requests with manual redirect handling (3xx).
    Logic copied from DockerPuller._make_request.
    """
    MAX_REDIRECTS = 5
    redirect_count = 0
    current_host = host
    current_url = url

    while redirect_count < MAX_REDIRECTS:
        conn = None
        try:
            parsed_url = urllib.parse.urlparse(f"https://{current_host}{current_url}")
            current_host = parsed_url.netloc
            current_path = parsed_url.path + (
                "?" + parsed_url.query if parsed_url.query else ""
            )

            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(current_host, context=context)

            # KEY LOGIC FROM YOUR CLASS: Removing the Authorization header after the first redirect
            req_headers = headers.copy()
            if redirect_count > 0 and "Authorization" in req_headers:
                # After redirecting to the storage server (blobs), authorization is often built into the link
                del req_headers["Authorization"]

            conn.request(method, current_path, headers=req_headers)
            response = conn.getresponse()

            # Handling redirects (Status 3xx)
            if response.status in (301, 302, 307, 308):
                new_location = response.getheader("Location")
                if not new_location:
                    raise Exception("Redirect without Location header.")

                new_parsed_url = urllib.parse.urlparse(new_location)
                current_host = new_parsed_url.netloc
                current_url = new_parsed_url.path + (
                    "?" + new_parsed_url.query if new_parsed_url.query else ""
                )

                redirect_count += 1
                conn.close()
                continue

            if response.status == 200:
                if save_path:
                    with open(save_path, "wb") as f:
                        shutil.copyfileobj(response, f)
                    return "File saved", 200
                else:
                    data = response.read().decode("utf-8")
                    return data, 200
            else:
                error_data = response.read().decode("utf-8", errors="ignore")
                logger.error(
                    f"HTTP Status {response.status} for {current_host}{current_path}"
                )
                return error_data, response.status

        except Exception as e:
            logger.error(f"Error during request to {current_host}{current_path}: {e}")
            return None, None
        finally:
            if conn:
                conn.close()

    if redirect_count == MAX_REDIRECTS:
        logger.error("Maximum redirect limit reached.")
        return None, None

    return None, None


def download_image(full_image_arg: str):
    """
    Downloads a Docker image (v2 Registry API) using proven logic from the
    DockerPuller class (manual redirect handling and token removal for S3).

    Preserves the functionality of the old download_image (downloads, creates tar, extracts RootFS).

    Args:
        full_image_arg (str): Image name with tag, e.g., 'alpine:latest'.
    """
    architecture = get_arch()
    token = ""
    digest = ""
    layer_digests = []
    config_digest = ""
    config_output_path = ""
    config_filename_short = ""
    final_tar_name = None
    image, tag = parse_image(full_image_arg)
    simple_tag = f"{image}:{tag}"
    logger.info(
        f"--- Starting manual pull of image {image}:{tag} ({architecture}) using pure Python ---"
    )

    def _step1_get_authorization_token():
        nonlocal token
        logger.info("1/8: Retrieving authorization token...")
        host = "auth.docker.io"
        url = f"/token?service=registry.docker.io&scope=repository:{image}:pull"
        response_data, status = request(host, url)
        if response_data is None or status != 200:
            raise Exception("Authentication server did not return a valid response.")
        try:
            token_json = json.loads(response_data)
            token = token_json.get("token")
        except json.JSONDecodeError:
            raise Exception("Failed to decode token response JSON.")
        if not token:
            logger.error(f"Server returned error: {response_data}")
            raise Exception("Failed to extract token.")
        logger.info("Token obtained successfully.")

    def _step2_3_get_manifest_list_and_digest():
        nonlocal digest
        logger.info(
            f"2/8 & 3/8: Retrieving Manifest List and extracting digest for {architecture}..."
        )
        host = "registry-1.docker.io"
        url = f"/v2/{image}/manifests/{tag}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.docker.distribution.manifest.list.v2+json",
        }
        manifest_list_data, status = request(host, url, headers=headers)
        if manifest_list_data is None or status != 200:
            raise Exception("Manifest list request failed.")

        manifest_list = json.loads(manifest_list_data)
        digest_found = None
        for manifest in manifest_list.get("manifests", []):
            platform_info = manifest.get("platform", {})
            if platform_info.get("architecture") == architecture:
                digest_found = manifest.get("digest")
                break
        if not digest_found:
            raise Exception(f"No digest found for architecture {architecture}.")
        digest = digest_found
        logger.info(f"Digest found for {architecture}: {digest}")

    def _step4_download_manifest():
        nonlocal layer_digests, config_digest
        logger.info("4/8: Downloading the actual image manifest using the digest...")
        manifest_path = os.path.join(BUILD_TEMP_DIR, "manifest.json")
        host = "registry-1.docker.io"
        url = f"/v2/{image}/manifests/{digest}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.docker.distribution.manifest.v2+json",
        }

        response_data, status = request(host, url, headers=headers)
        if status != 200:
            raise Exception("Failed to download manifest.")

        # Saving the manifest to a file, then loading it (as in DockerPuller)
        with open(manifest_path, "w") as f:
            f.write(response_data)

        manifest_data = json.loads(response_data)
        layer_digests = [layer["digest"] for layer in manifest_data.get("layers", [])]

        # Optionally saving the list of digests to a file (as in DockerPuller, for order)
        blobs_list_path = os.path.join(BUILD_TEMP_DIR, "blobs_list.txt")
        with open(blobs_list_path, "w") as f:
            for dgst in layer_digests:
                f.write(f"{dgst}\n")

        config_digest = manifest_data.get("config", {}).get("digest")
        if not layer_digests or not config_digest:
            raise Exception(
                "Manifest parsing failed (empty layers or config digest missing)."
            )
        logger.info(
            f"Manifest saved and layer list ({len(layer_digests)} layers) extracted."
        )

    def _step5_download_layers():
        logger.info("5/8: Downloading layers (blobs)...")
        os.makedirs(IMAGE_LAYERS_DIR, exist_ok=True)
        host = "registry-1.docker.io"
        download_count = 0
        for blob_sum in layer_digests:
            hash_part = blob_sum.split(":", 1)[1]
            logger.info(f"   -> Downloading: {blob_sum}...")
            layer_path = os.path.join(IMAGE_LAYERS_DIR, f"{hash_part}.tar.gz")
            url = f"/v2/{image}/blobs/{blob_sum}"
            headers = {"Authorization": f"Bearer {token}"}

            # Use _make_request, which handles redirects and removes the header
            result, status = request(host, url, headers=headers, save_path=layer_path)
            if status == 200:
                download_count += 1
            else:
                raise Exception(
                    f"Failed to download layer {blob_sum}. Status: {status}"
                )
        logger.info(
            f"Successfully downloaded {download_count} layers to {IMAGE_LAYERS_DIR}."
        )

    def _step6_download_config():
        nonlocal config_output_path, config_filename_short
        logger.info("6/8: Downloading the configuration file...")
        config_filename = config_digest.split(":", 1)[1]
        config_output_path = os.path.join(BUILD_TEMP_DIR, f"{config_filename}.json")
        config_filename_short = f"{config_filename}.json"
        host = "registry-1.docker.io"
        url = f"/v2/{image}/blobs/{config_digest}"
        headers = {"Authorization": f"Bearer {token}"}

        # Use _make_request, which handles redirects and removes the header
        result, status = request(
            host, url, headers=headers, save_path=config_output_path
        )
        if status != 200:
            raise Exception(f"Failed to download configuration file. Status: {status}")
        logger.info(f"Configuration file saved as {config_output_path}.")

    def _step7_assemble_tar_archive():
        nonlocal final_tar_name
        logger.info("7/8: Assembling the image into a .tar archive...")
        os.makedirs(COMPOSE_DIR, exist_ok=True)

        # 1. Move the configuration file (we remove it from build_temp_dir)
        shutil.move(
            config_output_path, os.path.join(COMPOSE_DIR, config_filename_short)
        )

        layer_paths_for_manifest = []

        # 2. Copy and rename layers for the archive
        for blob_sum in layer_digests:
            hash_part = blob_sum.split(":", 1)[1]

            tar_gz_path = os.path.join(IMAGE_LAYERS_DIR, f"{hash_part}.tar.gz")
            compose_tar_path = os.path.join(COMPOSE_DIR, f"{hash_part}.tar")
            layer_paths_for_manifest.append(f"{hash_part}.tar")

            # Copy of the compressed file, but with a *.tar name
            shutil.copyfile(tar_gz_path, compose_tar_path)

            # Add the VERSION file (as in DockerPuller)
            with open(os.path.join(COMPOSE_DIR, f"{hash_part}.tar.version"), "w") as f:
                f.write("1.0\n")

        # 3. Create manifest.json
        layer_paths_json = ", ".join([f'"{h}"' for h in layer_paths_for_manifest])
        catalog_manifest = f"""[ {{
            "Config": "{config_filename_short}",
            "RepoTags": [ "{simple_tag}" ],
            "Layers": [ {layer_paths_json} ]
        }} ]"""

        with open(os.path.join(COMPOSE_DIR, "manifest.json"), "w") as manifest:
            manifest.write(catalog_manifest)

        # 4. Packaging into an archive
        final_tar_name = (
            f"{full_image_arg.replace('/', '_').replace(':', '_')}_loaded.tar"
        )

        with tarfile.open(final_tar_name, "w") as tar:
            for item in os.listdir(COMPOSE_DIR):
                tar.add(os.path.join(COMPOSE_DIR, item), arcname=item)

        logger.info(f"Image assembled into {final_tar_name}.")

    def _step8_extract_rootfs():
        logger.info(
            f"8/8: Extracting layers into a complete root filesystem in {CONTAINER_ROOT}..."
        )

        shutil.rmtree(CONTAINER_ROOT, ignore_errors=True)
        CONTAINER_ROOT.mkdir(parents=True, exist_ok=True)

        extraction_count = 0
        for blob_sum in layer_digests:
            hash_part = blob_sum.split(":", 1)[1]
            layer_tar_gz = os.path.join(IMAGE_LAYERS_DIR, f"{hash_part}.tar.gz")

            logger.info(f"   -> Extracting layer: {hash_part[:10]}...")

            # Using the tarfile module for decompression and extraction (as in DockerPuller)
            with tarfile.open(layer_tar_gz, "r:gz") as tar:
                tar.extractall(path=CONTAINER_ROOT)

            extraction_count += 1

        logger.info(
            f"Successfully extracted {extraction_count} layers to {CONTAINER_ROOT}."
        )

    # --- Main sequence (Replaces pull_image) ---
    try:
        os.makedirs(BUILD_TEMP_DIR, exist_ok=True)  # Creating the main temp directory

        _step1_get_authorization_token()
        _step2_3_get_manifest_list_and_digest()
        _step4_download_manifest()
        _step5_download_layers()
        _step6_download_config()
        _step7_assemble_tar_archive()
        _step8_extract_rootfs()

        # cleanup_download_artifacts()

    except Exception as e:
        logger.critical(f"\nDuring pull process: {e}")
        cleanup_download_artifacts()


# --- OTHER CORE LOGIC FUNCTIONS (Unchanged setup_network) ---


def setup_network(container_pid: int):
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
        ["ip", "link", "add", "name", BRIDGE_NAME, "type", "bridge"],
        ignore_stderr=True,
        check_error=False,
    )
    run_cmd_host(["ip", "link", "set", BRIDGE_NAME, "up"])
    run_cmd_host(
        ["ip", "addr", "add", bridge_ip, "dev", BRIDGE_NAME],
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
    run_cmd_host(["ip", "link", "set", veth_host, "master", BRIDGE_NAME])
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
            BRIDGE_NAME,
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
            BRIDGE_NAME,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ]
    )

    logger.info("6/8: Writing resolv.conf...")
    RESOLV_CONF_CONTENT = "nameserver 8.8.8.8\n" "nameserver 1.1.1.1\n"
    try:
        RESOLV_CONF_PATH = os.path.join(CONTAINER_ROOT, "etc", "resolv.conf")
        os.makedirs(os.path.join(CONTAINER_ROOT, "etc"), exist_ok=True)
        with open(RESOLV_CONF_PATH, "w") as f:
            f.write(RESOLV_CONF_CONTENT)
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
    )

    logger.info("--- NETWORK CONFIGURATION COMPLETE ---")


def remove_network_config():
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
            BRIDGE_NAME,
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
            BRIDGE_NAME,
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
        ["ip", "link", "show", BRIDGE_NAME], check_error=False, pipe_output=True
    ):
        logger.info(f"2. Removing bridge {BRIDGE_NAME}...")
        run_cmd_host(
            ["ip", "addr", "del", bridge_ip, "dev", BRIDGE_NAME],
            check_error=False,
            ignore_stderr=True,
        )
        run_cmd_host(
            ["ip", "link", "set", BRIDGE_NAME, "down"],
            check_error=False,
            ignore_stderr=True,
        )
        run_cmd_host(
            ["ip", "link", "del", BRIDGE_NAME], check_error=False, ignore_stderr=True
        )
        logger.info("Bridge removed.")
    else:
        logger.info("INFO: Bridge does not exist, skipping deletion.")
    logger.info("--- GLOBAL NETWORK CLEANUP COMPLETE ---")


def cleanup_container(container_pid: int, image_arg: str):
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

    logger.info(f"3. Removing container root filesystem: {CONTAINER_ROOT}")
    run_cmd_host(
        ["umount", f"{CONTAINER_ROOT}/dev"], check_error=False, ignore_stderr=True
    )
    run_cmd_host(
        ["umount", f"{CONTAINER_ROOT}/proc"], check_error=False, ignore_stderr=True
    )
    run_cmd_host(
        ["umount", f"{CONTAINER_ROOT}/sys"], check_error=False, ignore_stderr=True
    )

    shutil.rmtree(CONTAINER_ROOT, ignore_errors=True)
    logger.info("Root filesystem removed.")

    logger.info("4. Remove cgroup director...")
    shutil.rmtree(CGROUP_PATH, ignore_errors=True)

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


def main_create(image_arg: str):
    """Main function to create and run the container with PID 1 as /bin/sh."""

    # 1. Download and prepare the filesystem (MANUAL DOWNLOAD)
    download_image(image_arg)

    logger.info("\n2. Configuring cgroups and mounting /dev...")
    # Attempt to mount cgroup2, ignoring errors if already mounted
    run_cmd_host(
        ["mount", "-t", "cgroup2", "none", "/sys/fs/cgroup"],
        check_error=False,
        ignore_stderr=True,
    )
    cgroup_path_obj = Path(CGROUP_PATH)
    cgroup_path_obj.mkdir(parents=True, exist_ok=True)
    memory_path = Path(CGROUP_PATH) / "memory.max"
    try:
        with open(memory_path, "w") as f:
            f.write("256M")
        logger.info(f"Memory limit set to 256MB in {memory_path.name}")
    except OSError as e:
        logger.error(
            f"Failed to set memory limit: {e.strerror}. (Required permissions?)"
        )

    # 2. Writing CPU limit (instead of 'echo 50000 100000 > ...')
    cpu_path = Path(CGROUP_PATH) / "cpu.max"
    try:
        with open(cpu_path, "w") as f:
            f.write("50000 100000")
        logger.info(f"CPU limit set to 50% in {cpu_path.name}")
    except OSError as e:
        logger.error(f"Failed to set CPU limit: {e.strerror}. (Required permissions?)")

    run_cmd_host(["mount", "-t", "devtmpfs", "none", f"{CONTAINER_ROOT}/dev"])
    logger.info("Cgroups configured.")

    # 3. Launch the container process (Init Script)
    logger.info("\n3. Launching Init Script (PID 1) in the isolated environment...")

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
        f"--root={CONTAINER_ROOT}",
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
    run_cmd_host(["sh", "-c", f"echo {unshare_pid} > {CGROUP_PATH}/cgroup.procs"])

    try:
        setup_network(unshare_pid)

        logger.info("\n4. Network ready. Sending Handshake signal to PID 1...")
        run_cmd_host(
            ["rm", "-f", f"{CONTAINER_ROOT}/{NETWORK_READY_FLAG}"],
            check_error=False,
            ignore_stderr=True,
        )
        run_cmd_host(["touch", f"{CONTAINER_ROOT}/{NETWORK_READY_FLAG}"])

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
        remove_network_config()
        cleanup_container(unshare_pid, image_arg)
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


def main_remove(image_arg: str):
    """Main function to remove all resources."""
    unshare_pid = get_parent_pid_of_shell()
    remove_network_config()
    cleanup_container(unshare_pid, image_arg)
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

    args = parse_args()

    if args.command == "run":
        main_create(args.image_arg)
    elif args.command == "rm":
        main_remove(args.image_arg)

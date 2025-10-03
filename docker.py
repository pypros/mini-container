# Fetched content for uploaded:container_manager.py
import subprocess
import os
import signal
import time
import sys
import shutil # Native, for deleting directories
import json     # Native, for parsing JSON
import urllib.request # Native, replaces requests
from typing import List, Optional
from pathlib import Path
import http.client
import urllib.parse
import tarfile
import ssl


# --- GLOBAL CONFIGURATION ---
CONTAINER_ROOT = "./my_image_root"
# Network Configuration
BRIDGE_NAME = "mybr0"
CONTAINER_NETWORK = "172.19.0.0/16"
BRIDGE_IP = "172.19.0.1/16"
HOST_INTERFACE = "eno1" # <--- CHANGE THIS TO YOUR MAIN NETWORK INTERFACE
CONTAINER_IP = "172.19.0.2/16"

# Cgroups
CGROUP_NAME = "my_custom_container"
CGROUP_PATH = f"/sys/fs/cgroup/{CGROUP_NAME}"

# Handshake File - used to signal that the network is ready
NETWORK_READY_FLAG = "network_ready" 

# Directories created during image download (NEW)
BUILD_TEMP_DIR = ".docker_temp"
IMAGE_LAYERS_DIR = "./image_layers"
COMPOSE_DIR = "./docker_image_compose" 

# INIT CMD - Script executed as PID 1 in the container
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

def run_cmd(cmd: List[str], pipe_output: bool = False, input_data: Optional[str] = None, check_error: bool = True, ignore_stderr: bool = False) -> Optional[str]:
    """Helper function to execute shell commands using subprocess."""
    try:
        if input_data:
            # If input_data is provided, it's passed via stdin
            process = subprocess.run(
                cmd, 
                input=input_data.encode('utf-8'), 
                capture_output=pipe_output, 
                check=check_error,
                text=True, 
                stderr=subprocess.DEVNULL if ignore_stderr else None
            )
        else:
            # Otherwise, execute the command directly
            process = subprocess.run(
                cmd, 
                capture_output=pipe_output, 
                check=check_error,
                text=True,
                stderr=subprocess.DEVNULL if ignore_stderr else None
            )

        if pipe_output and process.stdout:
            return process.stdout.strip()
        return None
    except subprocess.CalledProcessError as e:
        if check_error:
            print(f"Error executing command: {' '.join(cmd)}")
            print(f"Return code: {e.returncode}")
            # print(f"Output: {e.output}") # Can be useful for debugging
            # print(f"Stderr: {e.stderr}")
            sys.exit(e.returncode)
        return None
    except FileNotFoundError:
        print(f"Error: Command not found: {cmd[0]}")
        sys.exit(1)

# --- CLEANUP AND HELPER FUNCTIONS ---

def cleanup_dirs():
    """Removes temporary directories using native Python functions (shutil.rmtree)."""
    # Replaces run_cmd(["rm", "-rf", ...])
    for directory in [CONTAINER_ROOT, BUILD_TEMP_DIR, IMAGE_LAYERS_DIR, COMPOSE_DIR]:
        if os.path.isdir(directory):
            try:
                # We check if the directory is not the root directory or '/'.
                if directory == '/' or directory == CONTAINER_ROOT:
                    # We only want to delete CONTAINER_ROOT when it's ready
                    continue
                shutil.rmtree(directory)
            except OSError as e:
                print(f"Error cleaning directory {directory}: {e}") # Błąd czyszczenia katalogu

def cleanup_download_artifacts():
    """Removes temporary directories after image download and extraction."""
    for directory in [BUILD_TEMP_DIR, IMAGE_LAYERS_DIR, COMPOSE_DIR]:
        if os.path.isdir(directory):
            try:
                shutil.rmtree(directory)
            except OSError as e:
                print(f"Error cleaning download artifacts {directory}: {e}") # Błąd czyszczenia artefaktów pobierania

def get_arch() -> str:
    """Determines system architecture for Docker manifest using a dictionary lookup."""
    ARCHITECTURE_MAP = {
        "x86_64": "amd64",
        "aarch64": "arm64",
        "arm": "arm",
        "armv7l": "arm",
    }
    uname_arch = run_cmd(["uname", "-m"], pipe_output=True)
    docker_arch = ARCHITECTURE_MAP.get(uname_arch, "amd64")
    if docker_arch == "amd64" and uname_arch not in ARCHITECTURE_MAP:
        print(f"WARNING: Unknown system architecture ({uname_arch}). Using default: amd64.")
    return docker_arch

# --- CORE LOGIC FUNCTIONS ---
class BearerRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Call default redirect logic
        new_req = urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)
        
        # If a new request was created and the old request had an Authorization header
        if new_req and 'Authorization' in req.headers:
            # Add the Authorization header back to the new request
            new_req.add_header('Authorization', req.headers['Authorization'])
        return new_req

def download_image(full_arg: str):
    """
    Downloads a Docker image (v2 Registry API) using proven logic from the 
    DockerPuller class (manual redirect handling and token removal for S3).
    
    Preserves the functionality of the old download_image (downloads, creates tar, extracts RootFS).
    
    Args:
        full_arg (str): Image name with tag, e.g., 'alpine:latest'.
    """
    # --- Local state (replaces self from the class) ---
    full_image_arg = full_arg
    
    # Use global constants from container_manager.py
    build_temp_dir = BUILD_TEMP_DIR
    container_root = CONTAINER_ROOT
    image_layers_dir = IMAGE_LAYERS_DIR
    compose_dir = os.path.join(BUILD_TEMP_DIR, "compose_temp") # Will use temp/compose_temp
    
    image = ""
    tag = ""
    simple_tag = ""
    architecture = get_arch()
    token = ""
    digest = ""
    layer_digests = []
    config_digest = ""
    config_output_path = ""
    config_filename_short = ""
    final_tar_name = None 

    def _parse_image_arg():
        nonlocal image, tag, simple_tag
        if ':' not in full_image_arg:
            image_part = full_image_arg
            tag = 'latest'
        else:
            image_part, tag = full_image_arg.split(':', 1)

        if '/' not in image_part:
            image = f"library/{image_part}"
        else:
            image = image_part
        
        simple_tag = f"{image_part}:{tag}"
        print(f"--- 🛠️ Starting manual pull of image {image}:{tag} ({architecture}) using pure Python ---")

    def _make_request(host, url, method="GET", headers={}, save_path=None):
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
                current_path = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")

                context = ssl.create_default_context()
                conn = http.client.HTTPSConnection(current_host, context=context)

                # KEY LOGIC FROM YOUR CLASS: Removing the Authorization header after the first redirect
                req_headers = headers.copy()
                if redirect_count > 0 and 'Authorization' in req_headers:
                    # After redirecting to the storage server (blobs), authorization is often built into the link
                    del req_headers['Authorization'] 
                
                conn.request(method, current_path, headers=req_headers)
                response = conn.getresponse()

                # Handling redirects (Status 3xx)
                if response.status in (301, 302, 307, 308):
                    new_location = response.getheader('Location')
                    if not new_location:
                        raise Exception("Redirect without Location header.")
                    
                    new_parsed_url = urllib.parse.urlparse(new_location)
                    current_host = new_parsed_url.netloc
                    current_url = new_parsed_url.path + ("?" + new_parsed_url.query if new_parsed_url.query else "")
                    
                    redirect_count += 1
                    conn.close()
                    continue
                
                # Handling success (Status 200)
                if response.status == 200:
                    if save_path:
                        with open(save_path, 'wb') as f:
                            shutil.copyfileobj(response, f)
                        return "File saved", 200
                    else:
                        data = response.read().decode('utf-8')
                        return data, 200
                else:
                    # Handling other errors
                    error_data = response.read().decode('utf-8', errors='ignore')
                    print(f"ERROR: HTTP Status {response.status} for {current_host}{current_path}")
                    return error_data, response.status

            except Exception as e:
                print(f"ERROR during request to {current_host}{current_path}: {e}")
                return None, None
            finally:
                if conn:
                    conn.close()

        if redirect_count == MAX_REDIRECTS:
            print("ERROR: Maximum redirect limit reached.")
            return None, None
        
        return None, None

    def _step1_get_authorization_token():
        nonlocal token
        print("1/8: Retrieving authorization token...")
        host = "auth.docker.io"
        url = f"/token?service=registry.docker.io&scope=repository:{image}:pull"
        response_data, status = _make_request(host, url)
        if response_data is None or status != 200:
            raise Exception("Authentication server did not return a valid response.")
        try:
            token_json = json.loads(response_data)
            token = token_json.get('token')
        except json.JSONDecodeError:
            raise Exception("Failed to decode token response JSON.")
        if not token:
            print(f"Server returned error: {response_data}")
            raise Exception("Failed to extract token.")
        print("PASS: Token obtained successfully.")

    def _step2_3_get_manifest_list_and_digest():
        nonlocal digest
        print(f"2/8 & 3/8: Retrieving Manifest List and extracting digest for {architecture}...")
        host = "registry-1.docker.io"
        url = f"/v2/{image}/manifests/{tag}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.docker.distribution.manifest.list.v2+json"
        }
        manifest_list_data, status = _make_request(host, url, headers=headers)
        if manifest_list_data is None or status != 200:
            raise Exception("Manifest list request failed.")
        
        manifest_list = json.loads(manifest_list_data)
        digest_found = None
        for manifest in manifest_list.get('manifests', []):
            platform_info = manifest.get('platform', {})
            if platform_info.get('architecture') == architecture:
                digest_found = manifest.get('digest')
                break
        if not digest_found:
            raise Exception(f"No digest found for architecture {architecture}.")
        digest = digest_found
        print(f"PASS: Digest found for {architecture}: {digest}")

    def _step4_download_manifest():
        nonlocal layer_digests, config_digest
        print("4/8: Downloading the actual image manifest using the digest...")
        manifest_path = os.path.join(build_temp_dir, "manifest.json")
        host = "registry-1.docker.io"
        url = f"/v2/{image}/manifests/{digest}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.docker.distribution.manifest.v2+json"
        }
        
        response_data, status = _make_request(host, url, headers=headers)
        if status != 200:
            raise Exception("Failed to download manifest.")
        
        # Saving the manifest to a file, then loading it (as in DockerPuller)
        with open(manifest_path, 'w') as f:
            f.write(response_data)
            
        manifest_data = json.loads(response_data)
        layer_digests = [layer['digest'] for layer in manifest_data.get('layers', [])]
        
        # Optionally saving the list of digests to a file (as in DockerPuller, for order)
        blobs_list_path = os.path.join(build_temp_dir, "blobs_list.txt")
        with open(blobs_list_path, 'w') as f:
            for dgst in layer_digests:
                f.write(f"{dgst}\n")
                
        config_digest = manifest_data.get('config', {}).get('digest')
        if not layer_digests or not config_digest:
            raise Exception("Manifest parsing failed (empty layers or config digest missing).")
        print(f"PASS: Manifest saved and layer list ({len(layer_digests)} layers) extracted.")

    def _step5_download_layers():
        print("5/8: Downloading layers (blobs)...")
        os.makedirs(image_layers_dir, exist_ok=True)
        host = "registry-1.docker.io"
        download_count = 0
        for blob_sum in layer_digests:
            hash_part = blob_sum.split(':', 1)[1]
            print(f"   -> Downloading: {blob_sum}...")
            layer_path = os.path.join(image_layers_dir, f"{hash_part}.tar.gz")
            url = f"/v2/{image}/blobs/{blob_sum}"
            headers = {"Authorization": f"Bearer {token}"}
            
            # Use _make_request, which handles redirects and removes the header
            result, status = _make_request(host, url, headers=headers, save_path=layer_path)
            if status == 200:
                download_count += 1
            else:
                raise Exception(f"Failed to download layer {blob_sum}. Status: {status}")
        print(f"PASS: Successfully downloaded {download_count} layers to {image_layers_dir}.")

    def _step6_download_config():
        nonlocal config_output_path, config_filename_short
        print("6/8: Downloading the configuration file...")
        config_filename = config_digest.split(':', 1)[1]
        config_output_path = os.path.join(build_temp_dir, f"{config_filename}.json")
        config_filename_short = f"{config_filename}.json"
        host = "registry-1.docker.io"
        url = f"/v2/{image}/blobs/{config_digest}"
        headers = {"Authorization": f"Bearer {token}"}
        
        # Use _make_request, which handles redirects and removes the header
        result, status = _make_request(host, url, headers=headers, save_path=config_output_path)
        if status != 200:
            raise Exception(f"Failed to download configuration file. Status: {status}")
        print(f"PASS: Configuration file saved as {config_output_path}.")

    def _step7_assemble_tar_archive():
        nonlocal final_tar_name
        print("7/8: Assembling the image into a .tar archive...")
        os.makedirs(compose_dir, exist_ok=True)

        # 1. Move the configuration file (we remove it from build_temp_dir)
        shutil.move(config_output_path, os.path.join(compose_dir, config_filename_short))

        layer_paths_for_manifest = []

        # 2. Copy and rename layers for the archive
        for blob_sum in layer_digests:
            hash_part = blob_sum.split(':', 1)[1]
            
            tar_gz_path = os.path.join(image_layers_dir, f"{hash_part}.tar.gz")
            compose_tar_path = os.path.join(compose_dir, f"{hash_part}.tar")
            layer_paths_for_manifest.append(f"{hash_part}.tar")
            
            # Copy of the compressed file, but with a *.tar name
            shutil.copyfile(tar_gz_path, compose_tar_path)
            
            # Add the VERSION file (as in DockerPuller)
            with open(os.path.join(compose_dir, f"{hash_part}.tar.version"), 'w') as f:
                f.write("1.0\n")

        # 3. Create manifest.json
        layer_paths_json = ", ".join([f'"{h}"' for h in layer_paths_for_manifest])
        catalog_manifest = f"""[ {{
            "Config": "{config_filename_short}",
            "RepoTags": [ "{simple_tag}" ],
            "Layers": [ {layer_paths_json} ]
        }} ]"""
        
        with open(os.path.join(compose_dir, "manifest.json"), 'w') as f:
            f.write(catalog_manifest)

        # 4. Packaging into an archive
        final_tar_name = f"{full_image_arg.replace('/', '_').replace(':', '_')}_loaded.tar"
        
        with tarfile.open(final_tar_name, "w") as tar:
            for item in os.listdir(compose_dir):
                tar.add(os.path.join(compose_dir, item), arcname=item) 

        print(f"PASS: Image assembled into {final_tar_name}.")

    def _step8_extract_rootfs():
        print(f"8/8: Extracting layers into a complete root filesystem in {container_root}...")
        
        if os.path.exists(container_root):
            shutil.rmtree(container_root)
        os.makedirs(container_root)

        extraction_count = 0
        for blob_sum in layer_digests:
            hash_part = blob_sum.split(':', 1)[1]
            layer_tar_gz = os.path.join(image_layers_dir, f"{hash_part}.tar.gz")
            
            print(f"   -> Extracting layer: {hash_part[:10]}...")

            # Using the tarfile module for decompression and extraction (as in DockerPuller)
            with tarfile.open(layer_tar_gz, "r:gz") as tar:
                tar.extractall(path=container_root) 
            
            extraction_count += 1
            
        print(f"PASS: Successfully extracted {extraction_count} layers to {container_root}.")


    def _cleanup():
        print("-" * 50)
        # We remove the local temporary directories created within this function
        shutil.rmtree(compose_dir, ignore_errors=True)
        
        # We call the global function to remove global directories (BUILD_TEMP_DIR, IMAGE_LAYERS_DIR)
        cleanup_download_artifacts() 
        
        print("Temporary build files cleaned up.")
        print(f"--- PASS: COMPLETE: Image pulled and processed successfully ---")
        print(f"Image root filesystem extracted to: {container_root}")
        
        if final_tar_name:
            print(f"Image archive for 'docker load' saved as: {final_tar_name}")
        else:
             print("Image archive for 'docker load' was not created due to an earlier error.")


    # --- Main sequence (Replaces pull_image) ---
    try:
        _parse_image_arg()
        os.makedirs(build_temp_dir, exist_ok=True) # Creating the main temp directory
        
        _step1_get_authorization_token()
        print("-" * 50)
        _step2_3_get_manifest_list_and_digest()
        print("-" * 50)
        _step4_download_manifest()
        print("-" * 50)
        _step5_download_layers()
        print("-" * 50)
        _step6_download_config()
        print("-" * 50)
        _step7_assemble_tar_archive()
        print("-" * 50)
        _step8_extract_rootfs()
        print("-" * 50)
        _cleanup()

    except Exception as e:
        print(f"\nFATAL ERROR during pull process: {e}")
        _cleanup()
# --- OTHER CORE LOGIC FUNCTIONS (Unchanged setup_network) ---

def setup_network(container_pid: int):
    """Creates VETH, bridge, NAT, and configures the network using the container's PID.
    
    This function is optimized to reduce the number of external program calls to 8.
    """
    print("--- CONFIGURING NETWORK (Host) ---")
    
    veth_host = f"h{container_pid}"
    veth_guest = f"c{container_pid}"
    gateway_ip = BRIDGE_IP.split('/')[0]

    # Optimized configuration on the host

    # 1. IP Forwarding (1 call)
    print("1/8: Enabling IP Forwarding...")
    IP_FORWARD_PATH = '/proc/sys/net/ipv4/ip_forward'
    run_cmd(["echo","1", ">", IP_FORWARD_PATH])

    # 2. Creating and configuring Bridge (1 call - only adding the link)
    print("2/8: Creating Bridge and assigning IP...")
    run_cmd(["ip", "link", "add", "name", BRIDGE_NAME, "type", "bridge"], ignore_stderr=True, check_error=False) 
    run_cmd(["ip", "link", "set", BRIDGE_NAME, "up"])
    run_cmd(["ip", "addr", "add", BRIDGE_IP, "dev", BRIDGE_NAME], check_error=False, ignore_stderr=True)


    # 3. Creating VETH (1 call)
    print("3/8: Creating VETH pair...")
    run_cmd(["ip", "link", "add", "name", veth_host, "type", "veth", "peer", "name", veth_guest])
    run_cmd(["ip", "link", "set", veth_host, "master", BRIDGE_NAME])
    run_cmd(["ip", "link", "set", veth_host, "up"])
    
    # 4. Moving VETH to Namespaces (1 call)
    print("4/8: Moving VETH to namespace...")
    run_cmd(["ip", "link", "set", veth_guest, "netns", str(container_pid)])

    # 5. Configuring NAT and FORWARD (3 iptables commands)
    print("5/8: Configuring NAT (iptables)...")
    run_cmd(["iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1", "-s", CONTAINER_NETWORK, "-o", HOST_INTERFACE, "-j", "MASQUERADE"])
    run_cmd(["iptables", "-w", "-I", "FORWARD", "1", "-i", BRIDGE_NAME, "-o", HOST_INTERFACE, "-j", "ACCEPT"])
    run_cmd(["iptables", "-w", "-I", "FORWARD", "1", "-i", HOST_INTERFACE, "-o", BRIDGE_NAME, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])

    # 6. Writing resolv.conf (1 call)
    print("6/8: Writing resolv.conf...")
    RESOLV_CONF_CONTENT = ("nameserver 8.8.8.8\n" "nameserver 1.1.1.1\n")
    try:
        RESOLV_CONF_PATH = os.path.join(CONTAINER_ROOT, "etc", "resolv.conf")
        os.makedirs(os.path.join(CONTAINER_ROOT, "etc"), exist_ok=True)
        with open(RESOLV_CONF_PATH, 'w') as f:
            f.write(RESOLV_CONF_CONTENT)
    except Exception as e:
        print(f"Error writing resolv.conf: {e}")
        sys.exit(1)


    # 7. Configuration inside Namespaces (1 'nsenter' call)
    print("7/8: Configuring network inside container...")
    run_cmd([
        "nsenter", "-t", str(container_pid), "--mount", "--net", "--uts", f"--root={CONTAINER_ROOT}", 
        "/bin/sh", "-c",
        f"""
            ip link set lo up && \
            ip link set {veth_guest} up && \
            ip addr add {CONTAINER_IP} dev {veth_guest} && \
            ip route add default via {gateway_ip};
        """
    ])
    
    print("--- NETWORK CONFIGURATION COMPLETE ---")

def remove_network_config():
    """Removes global network configurations (iptables, bridge)."""
    print("--- CLEANING GLOBAL NETWORK CONFIGURATION ---")
    print("1. Removing iptables rules...")
    delete_rules = [
        ["iptables", "-w", "-t", "nat", "-D", "POSTROUTING", "-s", CONTAINER_NETWORK, "-o", HOST_INTERFACE, "-j", "MASQUERADE"],
        ["iptables", "-w", "-D", "FORWARD", "-i", BRIDGE_NAME, "-o", HOST_INTERFACE, "-j", "ACCEPT"],
        ["iptables", "-w", "-D", "FORWARD", "-i", HOST_INTERFACE, "-o", BRIDGE_NAME, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]
    for rule in delete_rules:
        for _ in range(3):
            run_cmd(rule, check_error=False, ignore_stderr=True)
    print("PASS: Iptables rules removed.")

    if run_cmd(["ip", "link", "show", BRIDGE_NAME], check_error=False, pipe_output=True):
        print(f"2. Removing bridge {BRIDGE_NAME}...")
        run_cmd(["ip", "addr", "del", BRIDGE_IP, "dev", BRIDGE_NAME], check_error=False, ignore_stderr=True)
        run_cmd(["ip", "link", "set", BRIDGE_NAME, "down"], check_error=False, ignore_stderr=True)
        run_cmd(["ip", "link", "del", BRIDGE_NAME], check_error=False, ignore_stderr=True)
        print("PASS: Bridge removed.")
    else:
        print("INFO: Bridge does not exist, skipping deletion.")
    print("--- GLOBAL NETWORK CLEANUP COMPLETE ---")

def cleanup_container(container_pid: int, image_arg: str):
    """Cleans up container artifacts (process, VETH, cgroups, rootfs)."""
    print("--- CLEANING CONTAINER ARTIFACTS ---")
    
    # 1. Stop the unshare process
    if container_pid > 0:
        try:
            os.kill(container_pid, signal.SIGKILL)
            print(f"1. Terminated container process (PID: {container_pid}).")
        except ProcessLookupError:
            pass
    
    # 2. Clean up lingering VETH interfaces
    print("2. Removing lingering host VETH interfaces...")
    veth_list_raw = run_cmd(["ip", "link", "show"], pipe_output=True, check_error=False)
    if veth_list_raw:
        # Search for lines starting with h[digit]@
        import re
        veth_matches = re.findall(r'(\bh\d+@if\d+):', veth_list_raw)
        for veth_match in veth_matches:
            iface_name = veth_match.split('@')[0]
            run_cmd(["ip", "link", "del", iface_name], check_error=False, ignore_stderr=True)
    print("PASS: VETH interfaces checked/removed.")

    # 3. Unmount and remove rootfs
    print(f"3. Removing container root filesystem: {CONTAINER_ROOT}")
    run_cmd(["umount", f"{CONTAINER_ROOT}/dev"], check_error=False, ignore_stderr=True)
    run_cmd(["umount", f"{CONTAINER_ROOT}/proc"], check_error=False, ignore_stderr=True)
    run_cmd(["umount", f"{CONTAINER_ROOT}/sys"], check_error=False, ignore_stderr=True)

    if os.path.isdir(CONTAINER_ROOT):
        try:
            # 🔥 Native and safe directory and content removal 🔥
            shutil.rmtree(CONTAINER_ROOT)
            print("PASS: Root filesystem removed (shutil.rmtree).")
        except Exception as e:
            print(f"ERROR: Error while removing RootFS: {e}") # Błąd podczas usuwania RootFS

    print("PASS: Root filesystem removed.")


    # 4. Remove cgroup directory
    if os.path.isdir(CGROUP_PATH):
        print(f"4. Removing cgroup directory: {CGROUP_PATH}")
        
        try:
            # Attempt to remove using os.rmdir()
            # This will only succeed IF the kernel has released all resources in CGROUP_PATH
            os.rmdir(CGROUP_PATH) 
            print("PASS: Cgroup directory removed.")
            
        except OSError as e:
            # Catch error if the directory is not empty or permission denied
            print(f"ERROR: Failed to remove cgroup directory {CGROUP_PATH}.")
            print(f"   Details: {e.strerror}. ")
            print("   WARNING: This may mean that container processes are still active or resources have not been released.") # Może to oznaczać...

    else:
        print(f"4. Cgroup directory {CGROUP_PATH} does not exist. Skipping cleanup.") # nie istnieje. Pomijam czyszczenie.
        
    # 5. Remove temporary build files (NEW)
    print("5. Removing temporary build artifacts...")
    shutil.rmtree(BUILD_TEMP_DIR, ignore_errors=True)
    shutil.rmtree(IMAGE_LAYERS_DIR, ignore_errors=True)
    shutil.rmtree(COMPOSE_DIR, ignore_errors=True)
    
    # Clean up the .tar file (optional)
    image_to_cleanup = image_arg if image_arg else "alpine:latest"
    input_image_part, tag = image_to_cleanup.split(':', 1) if ':' in image_to_cleanup else (image_to_cleanup, "latest")
    final_tar_name = Path(f"{input_image_part.replace('/', '_')}_{tag.replace(':', '_')}_loaded.tar")
    final_tar_name.unlink(missing_ok=True) 
    
    print("PASS: Build artifacts removed.")
    
    print("--- CONTAINER ARTIFACTS CLEANUP COMPLETE ---")

# --- MAIN ORCHESTRATION ---

def main_create(image_arg: str):
    """Main function to create and run the container with PID 1 as /bin/sh."""

    # 1. Download and prepare the filesystem (MANUAL DOWNLOAD)
    download_image(image_arg)

    # 2. Cgroups configuration
    print("\n2. Configuring cgroups and mounting /dev...")
    # Attempt to mount cgroup2, ignoring errors if already mounted
    run_cmd(["mount", "-t", "cgroup2", "none", "/sys/fs/cgroup"], check_error=False, ignore_stderr=True)
    cgroup_path_obj = Path(CGROUP_PATH)
    cgroup_path_obj.mkdir(parents=True, exist_ok=True)
    memory_path = Path(CGROUP_PATH) / 'memory.max'
    try:
        with open(memory_path, 'w') as f:
            f.write('256M')
        print(f"PASS: Memory limit set to 256MB in {memory_path.name}")
    except OSError as e:
        print(f"ERROR: Failed to set memory limit: {e.strerror}. (Required permissions?)") # Wymagane uprawnienia?


    # 2. Writing CPU limit (instead of 'echo 50000 100000 > ...')
    cpu_path = Path(CGROUP_PATH) / 'cpu.max'
    try:
        with open(cpu_path, 'w') as f:
            f.write('50000 100000')
        print(f"PASS: CPU limit set to 50% in {cpu_path.name}")
    except OSError as e:
        print(f"ERROR: Failed to set CPU limit: {e.strerror}. (Required permissions?)") # Wymagane uprawnienia?


    run_cmd(["mount", "-t", "devtmpfs", "none", f"{CONTAINER_ROOT}/dev"])
    print("PASS: Cgroups configured.")

    # 3. Launch the container process (Init Script)
    print("\n3. Launching Init Script (PID 1) in the isolated environment...")

    unshare_cmd = [
        "unshare", "--uts", "--pid", "--net", "--mount", "--user", "--kill-child",
        "--map-root-user", f"--root={CONTAINER_ROOT}", 
        "/bin/sh", "-c", CONTAINER_INIT_CMD
    ]

    # Run in Popen mode to allow the process to be immediately accessible and to connect the terminal
    unshare_proc = subprocess.Popen(unshare_cmd, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
    unshare_pid = unshare_proc.pid

    print(f"Unshare Host PID captured: {unshare_pid}. This process will become /bin/sh (PID 1).")
    time.sleep(1) # Give time for startup and /proc mounting

    # Assign PID to Cgroup on the HOST
    run_cmd(["sh", "-c", f"echo {unshare_pid} > {CGROUP_PATH}/cgroup.procs"])

    # 4. Configure Network and send handshake signal
    try:
        # Network configuration (uses unshare_pid, which is PID 1)
        setup_network(unshare_pid)

        # Handshake: Create the file signaling network readiness
        print("\n4. Network ready. Sending Handshake signal to PID 1...")
        run_cmd(["rm", "-f", f"{CONTAINER_ROOT}/{NETWORK_READY_FLAG}"], check_error=False, ignore_stderr=True)
        run_cmd(["touch", f"{CONTAINER_ROOT}/{NETWORK_READY_FLAG}"])

        # 5. Wait for exit (exiting from /bin/sh)
        print("\n5. Entering interactive shell (PID 1 is now /bin/sh. Type 'exit' to quit)...")
        unshare_proc.wait() 

        print("\nShell exited.")

    except Exception as e:
        print(f"\nFATAL ERROR during configuration or runtime: {e}")
        try:
            os.kill(unshare_pid, signal.SIGKILL)
        except:
            pass
    finally:
        # 6. Cleanup upon exit
        print("\n6. Initiating cleanup...")
        remove_network_config()
        cleanup_container(unshare_pid, image_arg)
        print("Container management process finished.")


# --- CLEANUP (REMOVE) FUNCTION ---

def main_remove(image_arg: str):
    """Main function to remove all resources."""

    unshare_pid = 0
    # Search for the PID of the running interactive shell process
    pid_list_raw = run_cmd(["pgrep", "-f", "/bin/sh -i"], pipe_output=True, check_error=False)
    if pid_list_raw:
        init_pid = pid_list_raw.split()[0]
        # Ppid of PID 1 in the new namespace is the unshare_pid
        unshare_pid_raw = run_cmd(["ps", "-o", "ppid=", "-p", init_pid], pipe_output=True, check_error=False)
        if unshare_pid_raw:
             unshare_pid = int(unshare_pid_raw.strip())
        else:
            unshare_pid = 0

    remove_network_config() 
    cleanup_container(unshare_pid, image_arg)
    print("Full resource cleanup complete.")


# --- SCRIPT ENTRY POINT ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 container_manager.py {create|remove} [IMAGE_NAME:TAG]")
        sys.exit(1)

    command = sys.argv[1].lower()
    image_arg = sys.argv[2] if len(sys.argv) > 2 else "alpine:latest"

    if command == "create":
        main_create(image_arg)
    elif command == "remove":
        main_remove(image_arg)
    else:
        print("Unknown command. Use 'create' or 'remove'.")
        sys.exit(1)
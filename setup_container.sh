#!/bin/bash

# Set options to make the script exit on the first error
set -e

# --- GLOBAL VARIABLES AND SCRIPT ARGUMENT CHECKING ---

# $1 is the command (create/remove)
# $2 is the image argument (e.g., alpine:latest)

COMMAND="$1"
IMAGE_ARG="$2" # Capturing the image argument here

# Location for the container's root filesystem
CONTAINER_ROOT="./my_image_root" 
CGROUP_NAME="my_custom_container_$(date +%s)"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"

# Directories created during image download
BUILD_TEMP_DIR=".docker_temp"
IMAGE_LAYERS_DIR="./image_layers"
COMPOSE_DIR="./docker_image_compose"

# Check for valid script arguments
if [ "$COMMAND" = "create" ] && [ -z "$IMAGE_ARG" ]; then
    echo "Usage: $0 create <IMAGE_NAME>:<TAG>"
    echo "Example: $0 create alpine:latest"
    exit 1
fi
# --------------------------------------------------------------------------

download_image() {
    # This function now takes ONE argument: image:tag
    local FULL_ARG="$1"

    # --- Image Settings and Argument Parsing (local to function) ---
    
    # Split the argument (e.g., alpine:latest) into image part and tag
    if [[ "$FULL_ARG" != *:* ]]; then
        INPUT_IMAGE_PART="$FULL_ARG"
        TAG="latest"
    else
        # Use IFS (Internal Field Separator) to split by ':'
        IFS=':' read -r INPUT_IMAGE_PART TAG <<< "$FULL_ARG"
    fi

    # Determine the full image name for Docker Hub (e.g., alpine -> library/alpine)
    if [[ "$INPUT_IMAGE_PART" == *"/"* ]]; then
        IMAGE="$INPUT_IMAGE_PART"
    else
        IMAGE="library/$INPUT_IMAGE_PART"
    fi

    # Simplified tag for 'docker load' (e.g., alpine:latest)
    SIMPLE_TAG="${INPUT_IMAGE_PART}:${TAG}"

    # Automatic detection of system architecture
    UNAME_ARCH=$(uname -m)

    case "$UNAME_ARCH" in
        x86_64)
            ARCHITECTURE="amd64"
            ;;
        aarch64)
            ARCHITECTURE="arm64"
            ;;
        armv7l)
            ARCHITECTURE="arm"
            ;;
        *)
            echo "WARNING: Unknown system architecture ($UNAME_ARCH). Using default: amd64."
            ARCHITECTURE="amd64"
            ;;
    esac

    # --- Global Constants and Initialization ---

    # Directory for intermediate files (manifests, config, blob lists)
    mkdir -p "${BUILD_TEMP_DIR}"

    # Check if jq is installed
    if ! command -v jq &> /dev/null
    then
        echo "ERROR: 'jq' tool is not installed. It is required for JSON parsing."
        return 1
    fi

    echo "--- Starting manual pull of image ${IMAGE}:${TAG} (${ARCHITECTURE}) using curl ---"

    # --- Step 1: Get Authorization Token ---

    echo "1/8: Retrieving authorization token..."

    TOKEN_RESPONSE=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${IMAGE}:pull")

    if [[ -z "$TOKEN_RESPONSE" ]]; then
        echo "ERROR: Authentication server did not return a response. Check network connection."
        return 1
    fi

    TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.token')

    if [[ "${TOKEN}" == "null" || -z "${TOKEN}" ]]; then
        echo "ERROR: Failed to extract token. Server returned error:"
        echo "${TOKEN_RESPONSE}"
        return 1
    fi

    echo "PASS: Token obtained successfully."
    echo "--------------------------------------------------------"

    # --- Step 2 & 3: Get Manifest List and Extract Architecture Digest ---

    echo "2/8 & 3/8: Retrieving Manifest List and extracting digest for ${ARCHITECTURE}..."

    # Download Manifest List
    MANIFEST_LIST_RESPONSE=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
                                -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
                                "https://registry-1.docker.io/v2/${IMAGE}/manifests/${TAG}")

    # Extract the digest for the specific ARCHITECTURE
    DIGEST=$(echo "${MANIFEST_LIST_RESPONSE}" | jq -r --arg arch "${ARCHITECTURE}" '.manifests[] | select(.platform.architecture == $arch) | .digest')

    if [[ -z "${DIGEST}" ]]; then
        echo "ERROR: No digest found for architecture ${ARCHITECTURE}."
        echo "Check if ${IMAGE}:${TAG} supports this architecture."
        return 1
    fi

    echo "PASS: Digest found for ${ARCHITECTURE}: ${DIGEST}"
    echo "--------------------------------------------------------"

    # --- Step 4: Download the Actual Image Manifest ---

    echo "4/8: Downloading the actual image manifest using the digest..."

    # Save manifest.json inside the temporary directory
    curl -s -H "Authorization: Bearer ${TOKEN}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "https://registry-1.docker.io/v2/${IMAGE}/manifests/${DIGEST}" > "${BUILD_TEMP_DIR}/manifest.json"

    echo "PASS: Manifest saved to ${BUILD_TEMP_DIR}/manifest.json."

    # Verification
    if ! head -c 1 "${BUILD_TEMP_DIR}/manifest.json" | grep -q '{'; then
        echo "ERROR: manifest.json file is corrupted/empty. Error content:"
        cat "${BUILD_TEMP_DIR}/manifest.json"
        return 1
    fi

    # Extract the digests of all layers (blobs) and save to temporary file
    jq -r '.layers[].digest' "${BUILD_TEMP_DIR}/manifest.json" > "${BUILD_TEMP_DIR}/blobs_list.txt"

    if [ ! -s "${BUILD_TEMP_DIR}/blobs_list.txt" ]; then
        echo "ERROR: Layer list is empty. Manifest parsing error."
        return 1
    fi

    echo "PASS: List of layer digests saved to ${BUILD_TEMP_DIR}/blobs_list.txt."
    echo "--------------------------------------------------------"

    # --- Step 5: Download Layers (Blobs) ---

    echo "5/8: Downloading layers (blobs)..."

    mkdir -p "${IMAGE_LAYERS_DIR}"

    DOWNLOAD_COUNT=0
    while IFS= read -r BLOBSUM; do
        HASH=$(echo $BLOBSUM | cut -d':' -f2)
        
        echo "   -> Downloading: ${BLOBSUM}..."

        # Download a single layer to the dedicated image_layers directory
        curl -s -L -o "${IMAGE_LAYERS_DIR}/${HASH}.tar.gz" \
            -H "Authorization: Bearer ${TOKEN}" \
            "https://registry-1.docker.io/v2/${IMAGE}/blobs/${BLOBSUM}"
        
        DOWNLOAD_COUNT=$((DOWNLOAD_COUNT + 1))
    done < "${BUILD_TEMP_DIR}/blobs_list.txt"

    echo "PASS: Successfully downloaded ${DOWNLOAD_COUNT} layers to ${IMAGE_LAYERS_DIR}."
    echo "--------------------------------------------------------"

    # --- Step 6: Download the Configuration File ---

    echo "6/8: Downloading the configuration file..."

    # 1. Extract the digest of the configuration file from manifest.json
    CONFIG_DIGEST=$(jq -r '.config.digest' "${BUILD_TEMP_DIR}/manifest.json")

    if [[ -z "${CONFIG_DIGEST}" ]]; then
        echo "ERROR: Failed to extract configuration digest from manifest.json."
        return 1
    fi

    CONFIG_FILENAME=$(echo $CONFIG_DIGEST | cut -d':' -f2)
    CONFIG_OUTPUT_PATH="${BUILD_TEMP_DIR}/${CONFIG_FILENAME}.json" # Save inside the temporary directory

    # 2. Download the configuration blob
    curl -s -L -o "${CONFIG_OUTPUT_PATH}" \
        -H "Authorization: Bearer ${TOKEN}" \
        "https://registry-1.docker.io/v2/${IMAGE}/blobs/${CONFIG_DIGEST}"

    echo "PASS: Configuration file saved as ${CONFIG_OUTPUT_PATH}."
    echo "--------------------------------------------------------"

    # --- Step 7: Assemble the Image into a .tar Archive ---

    echo "7/8: Assembling the image into a .tar archive..."

    # 1. Create a temporary directory for image assembly (different from BUILD_TEMP_DIR)
    mkdir -p "${COMPOSE_DIR}"
    cd "${COMPOSE_DIR}"

    # 2. Move the configuration file from the temp directory into the compose directory
    mv ../${BUILD_TEMP_DIR}/${CONFIG_FILENAME}.json .

    # 3. Prepare layers:
    BLOB_COUNT=0
    # Read from the temporary blobs list
    while IFS= read -r BLOBSUM; do
        HASH=$(echo $BLOBSUM | cut -d':' -f2)
        LAYER_DIR="${HASH}"
        mkdir -p "${LAYER_DIR}"
        
        # Decompress the layer file into an uncompressed layer.tar
        gunzip -c "../${IMAGE_LAYERS_DIR}/${HASH}.tar.gz" > "${LAYER_DIR}/layer.tar"
        
        # Add a 'VERSION' file
        echo "1.0" > "${LAYER_DIR}/VERSION"
        
        BLOB_COUNT=$((BLOB_COUNT + 1))
    done < ../${BUILD_TEMP_DIR}/blobs_list.txt

    # 4. Create the new, required manifest.json (specific to the .tar archive format)
    # We use SIMPLE_TAG (e.g., alpine:latest)
    CATALOG_MANIFEST="[ {
        \"Config\": \"${CONFIG_FILENAME}.json\",
        \"RepoTags\": [ \"${SIMPLE_TAG}\" ],
        \"Layers\": [ "

    # Add layer paths to the manifest
    LAYER_HASHES=()
    while IFS= read -r BLOBSUM; do
        LAYER_HASHES+=("$(echo $BLOBSUM | cut -d':' -f2)")
    done < ../${BUILD_TEMP_DIR}/blobs_list.txt

    LAYER_PATHS=""
    for hash in "${LAYER_HASHES[@]}"; do
        LAYER_PATHS+=\"${hash}/layer.tar\",
    done

    # Remove the trailing comma and close the manifest
    LAYER_PATHS=${LAYER_PATHS%,}

    CATALOG_MANIFEST="${CATALOG_MANIFEST} ${LAYER_PATHS} ]
    } ]"

    echo "${CATALOG_MANIFEST}" > manifest.json

    # 5. Package into the final archive
    FINAL_TAR_NAME="../${INPUT_IMAGE_PART/\//_}_${TAG//:/_}_loaded.tar" # Output file name
    tar -c -f "${FINAL_TAR_NAME}" *

    cd ..

    echo "PASS: Image assembled into ${FINAL_TAR_NAME}."
    echo "--------------------------------------------------------"

    # --- Step 8: Extracting layers into a complete root filesystem ---

    echo "8/8: Extracting layers into a complete root filesystem in ${CONTAINER_ROOT}..."

    # Ensure the destination directory is clean and ready
    rm -rf "${CONTAINER_ROOT}" 
    mkdir -p "${CONTAINER_ROOT}"

    EXTRACTION_COUNT=0
    # Read from the temporary blobs list to ensure correct layer order
    while IFS= read -r BLOBSUM; do
        HASH=$(echo $BLOBSUM | cut -d':' -f2)
        LAYER_TAR_GZ="${IMAGE_LAYERS_DIR}/${HASH}.tar.gz"
        
        echo "   -> Extracting layer: ${HASH}..."

        # Use -xzf for explicit gZip decompression
        tar -xzf "${LAYER_TAR_GZ}" -C "${CONTAINER_ROOT}"
        
        EXTRACTION_COUNT=$((EXTRACTION_COUNT + 1))
    done < "${BUILD_TEMP_DIR}/blobs_list.txt"

    echo "PASS: Successfully extracted ${EXTRACTION_COUNT} layers to ${CONTAINER_ROOT}."
    echo "--------------------------------------------------------"

    echo "--- INFO: Image pulled and processed successfully. Temporary files will be cleaned by 'remove' command. ---"
    echo "Image root filesystem extracted to: ${CONTAINER_ROOT}"
    echo "Image archive for 'docker load' saved as: ${FINAL_TAR_NAME}"
}

# --------------------------------------------------------------------------

remove_container() {
    echo "--- Starting full cleanup ---"
    
    # 1. Unmount and remove container root
    echo "1. Removing container root filesystem: $CONTAINER_ROOT"
    # Attempt to unmount /dev first, ignore errors if not mounted
    sudo umount "$CONTAINER_ROOT/dev" 2>/dev/null || true
    sudo rm -rf "$CONTAINER_ROOT"

    # 2. Remove old cgroup
    if [ -d "$CGROUP_PATH" ]; then
        echo "2. Removing old cgroup: $CGROUP_PATH"
        sudo rmdir "$CGROUP_PATH" 2>/dev/null || true
    fi

    # 3. Remove all temporary build files
    echo "3. Removing temporary build artifacts..."
    
    # --- Logic for removing the .tar file ---
    
    local IMAGE_TO_CLEANUP="$IMAGE_ARG"
    
    # If IMAGE_ARG is empty, set default value for cleanup attempt
    if [ -z "$IMAGE_TO_CLEANUP" ]; then
        IMAGE_TO_CLEANUP="alpine:latest"
        echo "   -> INFO: IMAGE_ARG is missing. Attempting to clean default file: alpine_latest_loaded.tar"
    fi
    
    local INPUT_IMAGE_PART
    local TAG

    # Parse the image (either from arg $2 or default)
    if [[ "$IMAGE_TO_CLEANUP" != *:* ]]; then
        INPUT_IMAGE_PART="$IMAGE_TO_CLEANUP"
        TAG="latest"
    else
        IFS=':' read -r INPUT_IMAGE_PART TAG <<< "$IMAGE_TO_CLEANUP"
    fi
    
    # Build the exact filename: e.g. "alpine_latest_loaded.tar"
    local FINAL_TAR_NAME="${INPUT_IMAGE_PART/\//_}_${TAG//:/_}_loaded.tar"
    
    if [ -f "$FINAL_TAR_NAME" ]; then
        echo "   -> Removing final image archive: $FINAL_TAR_NAME"
        rm -f "$FINAL_TAR_NAME"
    else
        echo "   -> Image archive $FINAL_TAR_NAME not found (may be for a different image or already removed)."
    fi
    
    # -----------------------------------------------

    echo "   -> Removing intermediate build directory: $BUILD_TEMP_DIR"
    rm -rf "$BUILD_TEMP_DIR" # Contains manifests and configs
    
    echo "   -> Removing temporary image layers: $IMAGE_LAYERS_DIR"
    rm -rf "$IMAGE_LAYERS_DIR" # Contains raw downloaded .tar.gz files

    echo "   -> Removing image composition directory: $COMPOSE_DIR"
    rm -rf "$COMPOSE_DIR" # Contains uncompressed layers and manifest.json

    echo "--- PASS: Full cleanup complete. ---"
}

# --------------------------------------------------------------------------

create_container() {
    echo "Preparing the container environment..."

    # 1. Downloading the image
    echo "Downloading and preparing the filesystem using $IMAGE_ARG..."
    download_image "$IMAGE_ARG" 

    echo "Filesystem prepared at: $CONTAINER_ROOT"

    # Mount devtmpfs from the host into the container directory
    echo "Mounting /dev in the container..."
    sudo mount -t devtmpfs none "$CONTAINER_ROOT/dev"

    # Cgroups (Control Groups) configuration
    echo "Configuring cgroups for resource limiting..."
    if ! mountpoint -q /sys/fs/cgroup; then
        echo "Mounting cgroup2..."
        sudo mount -t cgroup2 none /sys/fs/cgroup
    fi

    sudo mkdir -p "$CGROUP_PATH"
    echo "Setting memory limit to 256MB..."
    sudo sh -c "echo 256M > $CGROUP_PATH/memory.max"
    echo "Setting CPU limit to 50%..."
    sudo sh -c "echo '50000 100000' > $CGROUP_PATH/cpu.max"
    echo "Cgroups configured."

    # Launching the Container with --kill-child
    echo "Launching the process in an isolated environment..."
    # The --map-root-user flag maps the host's UID/GID to the container's root user.
    sudo unshare \
        --uts \
        --pid \
        --net \
        --mount \
        --user \
        --kill-child \
        --map-root-user \
        --root="$CONTAINER_ROOT" \
        /bin/sh -c "
            # Setup environment inside the new namespace
            mount -t proc proc /proc;
            mount -t sysfs sys /sys;
            hostname 'my-alpine-host';
            echo 'Welcome to my Alpine container!';
            echo Container is running with PID: \$\$;
            /bin/sh
        "
}

# --- MAIN SCRIPT LOGIC ---

case "$COMMAND" in
    create)
        create_container
        ;;
    remove)
        remove_container
        ;;
    *)
        echo "Usage: $0 {create|remove} [IMAGE_NAME:TAG]"
        exit 1
        ;;
esac

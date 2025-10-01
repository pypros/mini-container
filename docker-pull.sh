#!/bin/bash

# --- Image Settings and Argument Parsing ---

# Check if exactly one argument was provided (image:tag)
if [ -z "$1" ] || [ ! -z "$2" ]; then
    echo "Usage: $0 <IMAGE_NAME>:<TAG>"
    echo "Example: $0 alpine:latest"
    echo "Example (with custom repository): $0 my_user/my_image:latest"
    exit 1
fi

FULL_ARG="$1"

# Split the argument (e.g., alpine:latest) into image part and tag
# If no colon is present, default to 'latest' tag
if [[ "$FULL_ARG" != *:* ]]; then
    INPUT_IMAGE_PART="$FULL_ARG"
    TAG="latest"
else
    # Use IFS (Internal Field Separator) to split by ':'
    IFS=':' read -r INPUT_IMAGE_PART TAG <<< "$FULL_ARG"
fi

# Determine the full image name for Docker Hub (e.g., alpine -> library/alpine)
if [[ "$INPUT_IMAGE_PART" == *"/"* ]]; then
    # If it contains a slash (e.g., my_user/my_image), use it as is
    IMAGE="$INPUT_IMAGE_PART"
else
    # If no slash (e.g., alpine), assume it's an official image (library/alpine)
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
        echo "⚠️ WARNING: Unknown system architecture ($UNAME_ARCH). Using default: amd64."
        ARCHITECTURE="amd64"
        ;;
esac

# --- Global Constants and Initialization ---

# Directory for intermediate files (manifests, config, blob lists)
BUILD_TEMP_DIR=".docker_temp"
mkdir -p "${BUILD_TEMP_DIR}"

# New directory for the extracted root filesystem
CONTAINER_ROOT="./my_image_root" 

# Check if jq is installed
if ! command -v jq &> /dev/null
then
    echo "ERROR: 'jq' tool is not installed. It is required for JSON parsing."
    exit 1
fi

echo "--- 🛠️ Starting manual pull of image ${IMAGE}:${TAG} (${ARCHITECTURE}) using curl ---"

# --- Step 1: Get Authorization Token ---

echo "1/8: Retrieving authorization token..." # Updated step count

TOKEN_RESPONSE=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${IMAGE}:pull")

if [[ -z "$TOKEN_RESPONSE" ]]; then
    echo "ERROR: Authentication server did not return a response. Check network connection."
    exit 1
fi

TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.token')

if [[ "${TOKEN}" == "null" || -z "${TOKEN}" ]]; then
    echo "ERROR: Failed to extract token. Server returned error:"
    echo "${TOKEN_RESPONSE}"
    exit 1
fi

echo "PASS: Token obtained successfully."
echo "--------------------------------------------------------"

# --- Step 2 & 3: Get Manifest List and Extract Architecture Digest ---

echo "2/8 & 3/8: Retrieving Manifest List and extracting digest for ${ARCHITECTURE}..." # Updated step count

# Download Manifest List
MANIFEST_LIST_RESPONSE=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
                            -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
                            "https://registry-1.docker.io/v2/${IMAGE}/manifests/${TAG}")

# Extract the digest for the specific ARCHITECTURE
DIGEST=$(echo "${MANIFEST_LIST_RESPONSE}" | jq -r --arg arch "${ARCHITECTURE}" '.manifests[] | select(.platform.architecture == $arch) | .digest')

if [[ -z "${DIGEST}" ]]; then
    echo "ERROR: No digest found for architecture ${ARCHITECTURE}."
    echo "Check if ${IMAGE}:${TAG} supports this architecture."
    exit 1
fi

echo "PASS: Digest found for ${ARCHITECTURE}: ${DIGEST}"
echo "--------------------------------------------------------"

# --- Step 4: Download the Actual Image Manifest ---

echo "4/8: Downloading the actual image manifest using the digest..." # Updated step count

# Save manifest.json inside the temporary directory
curl -s -H "Authorization: Bearer ${TOKEN}" \
     -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
     "https://registry-1.docker.io/v2/${IMAGE}/manifests/${DIGEST}" > "${BUILD_TEMP_DIR}/manifest.json"

echo "PASS: Manifest saved to ${BUILD_TEMP_DIR}/manifest.json."

# Verification
if ! head -c 1 "${BUILD_TEMP_DIR}/manifest.json" | grep -q '{'; then
    echo "ERROR: manifest.json file is corrupted/empty. Error content:"
    cat "${BUILD_TEMP_DIR}/manifest.json"
    exit 1
fi

# Extract the digests of all layers (blobs) and save to temporary file
jq -r '.layers[].digest' "${BUILD_TEMP_DIR}/manifest.json" > "${BUILD_TEMP_DIR}/blobs_list.txt"

if [ ! -s "${BUILD_TEMP_DIR}/blobs_list.txt" ]; then
    echo "ERROR: Layer list is empty. Manifest parsing error."
    exit 1
fi

echo "PASS: List of layer digests saved to ${BUILD_TEMP_DIR}/blobs_list.txt."
echo "--------------------------------------------------------"

# --- Step 5: Download Layers (Blobs) ---

echo "5/8: Downloading layers (blobs)..." # Updated step count

mkdir -p ./image_layers

DOWNLOAD_COUNT=0
while IFS= read -r BLOBSUM; do
    HASH=$(echo $BLOBSUM | cut -d':' -f2)
    
    echo "   -> Downloading: ${BLOBSUM}..."

    # Download a single layer to the dedicated image_layers directory
    curl -s -L -o "./image_layers/${HASH}.tar.gz" \
         -H "Authorization: Bearer ${TOKEN}" \
         "https://registry-1.docker.io/v2/${IMAGE}/blobs/${BLOBSUM}"
    
    DOWNLOAD_COUNT=$((DOWNLOAD_COUNT + 1))
done < "${BUILD_TEMP_DIR}/blobs_list.txt"

echo "PASS: Successfully downloaded ${DOWNLOAD_COUNT} layers to ./image_layers."
echo "--------------------------------------------------------"

# --- Step 6: Download the Configuration File ---

echo "6/8: Downloading the configuration file..." # Updated step count

# 1. Extract the digest of the configuration file from manifest.json
CONFIG_DIGEST=$(jq -r '.config.digest' "${BUILD_TEMP_DIR}/manifest.json")

if [[ -z "${CONFIG_DIGEST}" ]]; then
    echo "ERROR: Failed to extract configuration digest from manifest.json."
    exit 1
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

echo "7/8: Assembling the image into a .tar archive..." # Updated step count

# 1. Create a temporary directory for image assembly (different from BUILD_TEMP_DIR)
COMPOSE_DIR="./docker_image_compose"
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
    gunzip -c "../image_layers/${HASH}.tar.gz" > "${LAYER_DIR}/layer.tar"
    
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

# --- NEW Step 8: Extracting layers into a complete root filesystem ---

echo "8/8: Extracting layers into a complete root filesystem in ${CONTAINER_ROOT}..." # New step

# Ensure the destination directory is clean and ready
rm -rf "${CONTAINER_ROOT}" 
mkdir -p "${CONTAINER_ROOT}"

EXTRACTION_COUNT=0
# Read from the temporary blobs list to ensure correct layer order
while IFS= read -r BLOBSUM; do
    HASH=$(echo $BLOBSUM | cut -d':' -f2)
    LAYER_TAR_GZ="./image_layers/${HASH}.tar.gz"
    
    echo "   -> Extracting layer: ${HASH}..."

    # CORRECTED LINE: Used -xzf for explicit gZip decompression
    tar -xzf "${LAYER_TAR_GZ}" -C "${CONTAINER_ROOT}"
    
    EXTRACTION_COUNT=$((EXTRACTION_COUNT + 1))
done < "${BUILD_TEMP_DIR}/blobs_list.txt"

echo "PASS: Successfully extracted ${EXTRACTION_COUNT} layers to ${CONTAINER_ROOT}."
echo "--------------------------------------------------------"

# --- Cleanup ---
rm -rf "${COMPOSE_DIR}"
rm -rf "${BUILD_TEMP_DIR}" # Remove the temporary directory containing manifests and configs
rm -rf "./image_layers" # Also remove the raw downloaded layers

echo "--- PASS: COMPLETE: Image pulled and processed successfully ---"
echo "Image root filesystem extracted to: ${CONTAINER_ROOT}"
echo "Image archive for 'docker load' saved as: ${FINAL_TAR_NAME}"
echo "Temporary build files cleaned up."

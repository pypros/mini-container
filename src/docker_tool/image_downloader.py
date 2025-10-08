import json
import logging
import os
import shutil
import tarfile
from pathlib import Path

from .api_requests import request


class MissingTokenError(Exception):
    """Raised when a token cannot be obtained."""

    pass


class MissingManifestListError(Exception):
    """Raised when a token cannot be obtained."""

    pass


class MissingDigestError(Exception):
    """Raised when a digest cannot be found for architecture."""

    pass


class MissingManifestError(Exception):
    """Raised when a manifest cannot be downloaded."""

    pass


class MissingLayerDigestsError(Exception):
    """Raised when a layer digests cannot be obtained."""

    pass


class ManifestParsingError(Exception):
    """Raised when a manifest parsing fails."""

    pass


class LayerDownloadError(Exception):
    """Raised when a layer cannot be downloaded."""

    pass


class ConfigDownloadError(Exception):
    """Raised when the configuration file cannot be downloaded."""

    pass


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def get_authorization_token(image: str) -> str:
    logger.info("1/8: Retrieving authorization token...")
    host = "auth.docker.io"
    url = f"/token?service=registry.docker.io&scope=repository:{image}:pull"
    response_data, status = request(host, url)
    if response_data is None or status != 200:
        raise MissingTokenError(
            "Authentication server did not return a valid response."
        )
    try:
        token_json = json.loads(response_data)
        token = token_json.get("token")
    except json.JSONDecodeError as e:
        logging.exception("Failed to decode token response JSON.")
        raise MissingTokenError("Failed to decode token response JSON.") from e
    if not token:
        logger.error(f"Server returned error: {response_data}")
        raise MissingTokenError("Failed to extract token.")
    logger.info("Token obtained successfully.")
    return str(token)


def get_manifest_list_and_digest(
    image: str, tag: str, architecture: str, token: str
) -> str:
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
        raise MissingManifestListError("Manifest list request failed.")

    try:
        manifest_list = json.loads(manifest_list_data or "")
    except json.JSONDecodeError as e:
        logging.exception("Failed to decode manifest list response JSON.")
        raise MissingManifestListError(
            "Failed to decode manifest list response JSON."
        ) from e

    digest = None
    for manifest in manifest_list.get("manifests", []):
        platform_info = manifest.get("platform", {})
        if platform_info.get("architecture") == architecture:
            digest = manifest.get("digest")
            break
    if not digest:
        raise MissingDigestError(f"No digest found for architecture {architecture}.")
    logger.info(f"Digest found for {architecture}: {digest}")
    return str(digest)


def download_manifest(
    image: str, digest: str, token: str, build_temp_dir: Path
) -> tuple[list[str], str]:
    logger.info("4/8: Downloading the actual image manifest using the digest...")
    manifest_path = build_temp_dir / "manifest.json"
    host = "registry-1.docker.io"
    url = f"/v2/{image}/manifests/{digest}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.docker.distribution.manifest.v2+json",
    }

    response_data, status = request(host, url, headers=headers)
    if status != 200:
        raise MissingManifestError("Failed to download manifest.")

    # Saving the manifest to a file, then loading it (as in DockerPuller)
    with open(manifest_path, "w") as f:
        f.write(response_data or "")

    manifest_data = json.loads(response_data or "")
    layer_digests = [layer["digest"] for layer in manifest_data.get("layers", [])]

    if not layer_digests:
        raise MissingLayerDigestsError(
            "Manifest parsing failed (empty layers or config digest missing)."
        )

    # Optionally saving the list of digests to a file (as in DockerPuller, for order)
    blobs_list_path = build_temp_dir / "blobs_list.txt"
    with open(blobs_list_path, "w") as f:
        for layer_digest in layer_digests:
            f.write(f"{layer_digest}\n")

    config_digest = manifest_data.get("config", {}).get("digest")
    if not config_digest:
        raise ManifestParsingError(
            "Manifest parsing failed (empty layers or config digest missing)."
        )
    logger.info(
        f"Manifest saved and layer list ({len(layer_digests)} layers) extracted."
    )
    return layer_digests, config_digest


def download_layers(
    token: str, image: str, layer_digests: list[str], image_layers_dir: Path
) -> bool:
    logger.info("5/8: Downloading layers (blobs)...")
    image_layers_dir.mkdir(parents=True, exist_ok=True)
    host = "registry-1.docker.io"
    download_count = 0
    for blob_sum in layer_digests:
        hash_part = blob_sum.split(":", 1)[1]
        logger.info(f"   -> Downloading: {blob_sum}...")
        layer_path = image_layers_dir / f"{hash_part}.tar.gz"

        url = f"/v2/{image}/blobs/{blob_sum}"
        headers = {"Authorization": f"Bearer {token}"}

        # Use request, which handles redirects and removes the header
        result, status = request(host, url, headers=headers, save_path=str(layer_path))
        if status != 200:
            raise LayerDownloadError(
                f"Failed to download layer {blob_sum}. Status: {status}"
            )
        download_count += 1
    logger.info(
        f"Successfully downloaded {download_count} layers to {image_layers_dir}."
    )
    return True


def download_config(
    token: str,
    image: str,
    config_digest: str,
    build_temp_dir: Path,
) -> tuple[Path, str]:
    logger.info("6/8: Downloading the configuration file...")
    config_filename = config_digest.split(":", 1)[1]
    config_output_path = build_temp_dir / f"{config_filename}.json"
    config_filename_short = f"{config_filename}.json"
    host = "registry-1.docker.io"
    url = f"/v2/{image}/blobs/{config_digest}"
    headers = {"Authorization": f"Bearer {token}"}

    # Use request, which handles redirects and removes the header
    result, status = request(
        host, url, headers=headers, save_path=str(config_output_path)
    )
    if status != 200:
        raise ConfigDownloadError(
            f"Failed to download configuration file. Status: {status}"
        )
    logger.info(f"Configuration file saved as {config_output_path}.")
    return config_output_path, config_filename_short


def assemble_tar_archive(
    image: str,
    tag: str,
    full_image_arg: str,
    config_output_path: Path,
    config_filename_short: str,
    layer_digests: list[str],
    compose_dir: Path,
    image_layers_dir: Path,
) -> str:
    logger.info("7/8: Assembling the image into a .tar archive...")
    compose_dir.mkdir(parents=True, exist_ok=True)

    # 1. Move the configuration file (we remove it from build_temp_dir)
    shutil.move(str(config_output_path), str(compose_dir / config_filename_short))

    layer_paths_for_manifest = []

    # 2. Copy and rename layers for the archive
    for blob_sum in layer_digests:
        hash_part = blob_sum.split(":", 1)[1]

        tar_gz_path = image_layers_dir / f"{hash_part}.tar.gz"
        compose_tar_path = compose_dir / f"{hash_part}.tar"
        layer_paths_for_manifest.append(f"{hash_part}.tar")

        # Copy of the compressed file, but with a *.tar name
        shutil.copyfile(tar_gz_path, compose_tar_path)

        # Add the VERSION file (as in DockerPuller)
        with open(compose_dir / f"{hash_part}.tar.version", "w") as f:
            f.write("1.0\n")

    # 3. Create manifest.json
    layer_paths_json = ", ".join([f'"{h}"' for h in layer_paths_for_manifest])
    catalog_manifest = f"""[ {{
        "Config": "{config_filename_short}",
        "RepoTags": [ "{image}:{tag}" ],
        "Layers": [ {layer_paths_json} ]
    }} ]"""

    with open(compose_dir / "manifest.json", "w") as manifest:
        manifest.write(catalog_manifest)

    # 4. Packaging into an archive
    final_tar_name = f"{full_image_arg.replace('/', '_').replace(':', '_')}_loaded.tar"

    with tarfile.open(final_tar_name, "w") as tar:
        for item in os.listdir(compose_dir):
            tar.add(Path(compose_dir) / item, arcname=item)

    logger.info(f"Image assembled into {final_tar_name}.")
    return final_tar_name


def extract_root_file_system(
    layer_digests: list[str], image_layers_dir: Path, container_root: Path
) -> None:
    logger.info(
        f"8/8: Extracting layers into a complete root filesystem in {container_root}..."
    )

    shutil.rmtree(container_root, ignore_errors=True)
    container_root.mkdir(parents=True, exist_ok=True)

    extraction_count = 0
    for blob_sum in layer_digests:
        hash_part = blob_sum.split(":", 1)[1]
        layer_tar_gz = image_layers_dir / f"{hash_part}.tar.gz"

        logger.info(f"   -> Extracting layer: {hash_part[:10]}...")

        # Using the tarfile module for decompression and extraction (as in DockerPuller)
        with tarfile.open(layer_tar_gz, "r:gz") as tar:
            tar.extractall(path=container_root)

        extraction_count += 1

    logger.info(
        f"Successfully extracted {extraction_count} layers to {container_root}."
    )


def cleanup_download_artifacts(
    container_root: Path,
    build_temp_dir: Path,
    image_layers_dir: Path,
    compose_dir: Path,
) -> None:
    """Removes temporary directories after image download and extraction."""
    for directory in [container_root, build_temp_dir, image_layers_dir, compose_dir]:
        if os.path.isdir(str(directory)):
            try:
                shutil.rmtree(str(directory))
            except OSError as e:
                logger.error(f"Error cleaning download artifacts {directory}: {e}")


def download_image(
    full_image_arg: str,
    image: str,
    tag: str,
    architecture: str,
    build_temp_dir: Path,
    image_layers_dir: Path,
    container_root: Path,
    compose_dir: Path,
) -> None:
    """
    Downloads a Docker image (v2 Registry API) using proven logic from the
    DockerPuller class (manual redirect handling and token removal for S3).

    Preserves the functionality of the old download_image (downloads, creates tar, extracts RootFS).

    Args:
        full_image_arg (str): Image name with tag, e.g., 'alpine:latest'.
    """
    logger.info(
        f"--- Starting manual pull of image {image}:{tag} ({architecture}) using pure Python ---"
    )

    try:
        build_temp_dir.mkdir(parents=True, exist_ok=True)

        token = get_authorization_token(image)
        digest = get_manifest_list_and_digest(image, tag, architecture, token)
        layer_digests, config_digest = download_manifest(
            image, digest, token, build_temp_dir
        )
        download_layers(token, image, layer_digests, image_layers_dir)
        config_output_path, config_filename_short = download_config(
            token, image, config_digest, build_temp_dir
        )
        assemble_tar_archive(
            image,
            tag,
            full_image_arg,
            config_output_path,
            config_filename_short,
            layer_digests,
            compose_dir,
            image_layers_dir,
        )
        extract_root_file_system(layer_digests, image_layers_dir, container_root)

    except Exception as e:
        logger.critical(f"\nDuring pull process: {e}")
        cleanup_download_artifacts(
            container_root, build_temp_dir, image_layers_dir, compose_dir
        )

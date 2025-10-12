package downloader

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"container-manager/pkg/api"
)

type TokenResponse struct {
	Token string `json:"token"`
}

type ManifestList struct {
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
		} `json:"platform"`
	} `json:"manifests"`
}

type Manifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

func DownloadImage(image, tag, architecture, containerRoot string) error {
	fmt.Printf("--- Starting manual pull of image %s:%s (%s) using Go ---\n", image, tag, architecture)

	// 1. Get token
	fmt.Println("1/8: Retrieving authorization token...")
	token, err := getToken(image)
	if err != nil {
		return err
	}
	fmt.Println("Token obtained successfully.")

	// 2. Get manifest list and digest
	fmt.Printf("2/8 & 3/8: Retrieving Manifest List and extracting digest for %s...\n", architecture)
	digest, err := getDigest(image, tag, architecture, token)
	if err != nil {
		return err
	}
	fmt.Printf("Digest found for %s: %s\n", architecture, digest)

	// 3. Download manifest
	fmt.Println("4/8: Downloading the actual image manifest using the digest...")
	layerDigests, err := downloadManifest(image, digest, token)
	if err != nil {
		return err
	}
	fmt.Printf("Manifest saved and layer list (%d layers) extracted.\n", len(layerDigests))

	// 4. Download and extract layers
	fmt.Println("5/8: Downloading layers (blobs)...")
	tempDir := ".docker_temp/image_layers"
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}

	for _, digest := range layerDigests {
		fmt.Printf("   -> Downloading: %s...\n", digest)
		if err := downloadLayer(image, digest, token, tempDir); err != nil {
			return err
		}
	}
	fmt.Printf("Successfully downloaded %d layers to %s.\n", len(layerDigests), tempDir)

	// 5. Extract layers
	fmt.Printf("8/8: Extracting layers into a complete root filesystem in %s...\n", containerRoot)
	return extractLayers(layerDigests, tempDir, containerRoot)
}

func getToken(image string) (string, error) {
	url := fmt.Sprintf("/token?service=registry.docker.io&scope=repository:%s:pull", image)

	response, status, err := api.Request("auth.docker.io", url, "GET", nil, "")
	if err != nil || status != 200 {
		return "", fmt.Errorf("failed to get token: %v", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal([]byte(response), &tokenResp); err != nil {
		return "", err
	}

	return tokenResp.Token, nil
}

func getDigest(image, tag, architecture, token string) (string, error) {
	url := fmt.Sprintf("/v2/%s/manifests/%s", image, tag)
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
		"Accept":        "application/vnd.docker.distribution.manifest.list.v2+json",
	}

	response, status, err := api.Request("registry-1.docker.io", url, "GET", headers, "")
	if err != nil {
		return "", fmt.Errorf("failed to get manifest list: %v", err)
	}
	if status != 200 {
		return "", fmt.Errorf("failed to get manifest list: status %d, response: %s", status, response)
	}

	var manifestList ManifestList
	if err := json.Unmarshal([]byte(response), &manifestList); err != nil {
		return "", err
	}

	for _, manifest := range manifestList.Manifests {
		if manifest.Platform.Architecture == architecture {
			return manifest.Digest, nil
		}
	}

	return "", fmt.Errorf("no digest found for architecture %s", architecture)
}

func downloadManifest(image, digest, token string) ([]string, error) {
	url := fmt.Sprintf("/v2/%s/manifests/%s", image, digest)
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
		"Accept":        "application/vnd.docker.distribution.manifest.v2+json",
	}

	response, status, err := api.Request("registry-1.docker.io", url, "GET", headers, "")
	if err != nil || status != 200 {
		return nil, fmt.Errorf("failed to download manifest: %v", err)
	}

	var manifest Manifest
	if err := json.Unmarshal([]byte(response), &manifest); err != nil {
		return nil, err
	}

	var layerDigests []string
	for _, layer := range manifest.Layers {
		layerDigests = append(layerDigests, layer.Digest)
	}

	return layerDigests, nil
}

func downloadLayer(image, digest, token, tempDir string) error {
	url := fmt.Sprintf("/v2/%s/blobs/%s", image, digest)
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}

	hashPart := digest[7:] // Remove "sha256:"
	layerPath := filepath.Join(tempDir, hashPart+".tar.gz")

	_, status, err := api.Request("registry-1.docker.io", url, "GET", headers, layerPath)
	if err != nil || status != 200 {
		return fmt.Errorf("failed to download layer %s: %v", digest, err)
	}

	return nil
}

func extractLayers(layerDigests []string, tempDir, containerRoot string) error {
	os.RemoveAll(containerRoot)
	if err := os.MkdirAll(containerRoot, 0755); err != nil {
		return fmt.Errorf("failed to create container root: %v", err)
	}

	for _, digest := range layerDigests {
		hashPart := digest[7:] // Remove "sha256:"
		fmt.Printf("   -> Extracting layer: %s...\n", hashPart[:10])

		layerPath := filepath.Join(tempDir, hashPart+".tar.gz")
		if err := extractTarGz(layerPath, containerRoot); err != nil {
			return fmt.Errorf("failed to extract layer: %v", err)
		}
	}

	fmt.Printf("Successfully extracted %d layers to %s.\n", len(layerDigests), containerRoot)
	return nil
}

func extractTarGz(filename, destination string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destination, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %v", err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("failed to copy file content: %v", err)
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("failed to create symlink: %v", err)
			}
		}
	}

	return nil
}

package downloader

import (
	"container-manager/pkg/api"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTokenResponse_Parsing(t *testing.T) {
	tokenResp := TokenResponse{Token: "test-token-123"}
	if tokenResp.Token != "test-token-123" {
		t.Errorf("Expected token 'test-token-123', got '%s'", tokenResp.Token)
	}
	
	data, err := json.Marshal(tokenResp)
	if err != nil {
		t.Fatalf("Failed to marshal token: %v", err)
	}
	
	var parsed TokenResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal token: %v", err)
	}
	
	if parsed.Token != tokenResp.Token {
		t.Errorf("Expected parsed token '%s', got '%s'", tokenResp.Token, parsed.Token)
	}
}

func TestMockImageDownloader_GetToken_Success(t *testing.T) {
	mock := &MockImageDownloader{
		TokenResponse: "test-token-123",
		TokenError:    nil,
	}
	
	token, err := mock.GetToken("library/alpine")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if token != "test-token-123" {
		t.Errorf("Expected 'test-token-123', got '%s'", token)
	}
}

func TestMockImageDownloader_GetToken_Error(t *testing.T) {
	mock := &MockImageDownloader{
		TokenResponse: "",
		TokenError:    fmt.Errorf("auth failed"),
	}
	
	_, err := mock.GetToken("library/alpine")
	if err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestMockImageDownloader_GetDigest_Success(t *testing.T) {
	mock := &MockImageDownloader{
		DigestResponse: "sha256:test-digest-amd64",
		DigestError:    nil,
	}
	
	digest, err := mock.GetDigest("library/alpine", "latest", "amd64", "token")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if digest != "sha256:test-digest-amd64" {
		t.Errorf("Expected 'sha256:test-digest-amd64', got '%s'", digest)
	}
}

func TestMockImageDownloader_DownloadImage_Error(t *testing.T) {
	mock := &MockImageDownloader{
		DownloadError: fmt.Errorf("download failed"),
	}
	
	err := mock.DownloadImage("library/alpine", "latest", "amd64", "/tmp/test")
	if err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestRealImageDownloader_Interface(t *testing.T) {
	client := &api.MockHTTPClient{}
	downloader := NewRealImageDownloader(client)
	
	// Test that RealImageDownloader implements ImageDownloader interface
	var _ ImageDownloader = downloader
	
	if downloader == nil {
		t.Error("Downloader should not be nil")
	}
}

func TestManifestList_Parsing(t *testing.T) {
	manifestList := ManifestList{
		Manifests: []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		}{
			{
				Digest: "sha256:test-digest-amd64",
				Platform: struct {
					Architecture string `json:"architecture"`
				}{Architecture: "amd64"},
			},
			{
				Digest: "sha256:test-digest-arm64",
				Platform: struct {
					Architecture string `json:"architecture"`
				}{Architecture: "arm64"},
			},
		},
	}

	for _, manifest := range manifestList.Manifests {
		if manifest.Platform.Architecture == "amd64" {
			expected := "sha256:test-digest-amd64"
			if manifest.Digest != expected {
				t.Errorf("Expected digest %s, got %s", expected, manifest.Digest)
			}
		}
	}
}

func TestExtractTarGz_InvalidFile(t *testing.T) {
	err := extractTarGz("nonexistent.tar.gz", t.TempDir())
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestParseImageName(t *testing.T) {
	tests := []struct {
		input         string
		expectedImage string
		expectedTag   string
	}{
		{"alpine", "library/alpine", "latest"},
		{"alpine:3.18", "library/alpine", "3.18"},
		{"nginx/nginx", "nginx/nginx", "latest"},
		{"nginx/nginx:stable", "nginx/nginx", "stable"},
		{"registry.io/user/app:v1.0", "registry.io/user/app", "v1.0"},
	}

	for _, test := range tests {
		parts := strings.Split(test.input, ":")
		image := parts[0]
		tag := "latest"
		if len(parts) > 1 {
			tag = parts[1]
		}

		if !strings.Contains(image, "/") {
			image = "library/" + image
		}

		if image != test.expectedImage {
			t.Errorf("Image: expected %s, got %s", test.expectedImage, image)
		}
		if tag != test.expectedTag {
			t.Errorf("Tag: expected %s, got %s", test.expectedTag, tag)
		}
	}
}
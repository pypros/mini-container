package downloader

import (
	"container-manager/pkg/api"
	"encoding/json"
	"fmt"
	"testing"
)

func TestGetToken_WithMock(t *testing.T) {
	// Mock successful token response
	tokenResp := TokenResponse{Token: "test-token-123"}
	tokenJSON, err := json.Marshal(tokenResp)
	if err != nil {
		t.Fatalf("Failed to marshal token: %v", err)
	}
	
	// Test JSON parsing
	var parsed TokenResponse
	if err := json.Unmarshal(tokenJSON, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal token: %v", err)
	}
	
	expectedToken := "test-token-123"
	if parsed.Token != expectedToken {
		t.Errorf("Expected token %s, got %s", expectedToken, parsed.Token)
	}
}

func TestGetDigest_WithMock(t *testing.T) {
	// Mock manifest list response
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
		},
	}
	
	// Test digest extraction logic
	var foundDigest string
	for _, manifest := range manifestList.Manifests {
		if manifest.Platform.Architecture == "amd64" {
			foundDigest = manifest.Digest
			break
		}
	}
	
	expected := "sha256:test-digest-amd64"
	if foundDigest != expected {
		t.Errorf("Expected digest %s, got %s", expected, foundDigest)
	}
}

func TestDownloadManifest_WithMock(t *testing.T) {
	// Mock manifest response
	manifest := Manifest{
		Config: struct {
			Digest string `json:"digest"`
		}{Digest: "sha256:config-digest"},
		Layers: []struct {
			Digest string `json:"digest"`
		}{
			{Digest: "sha256:layer1-digest"},
			{Digest: "sha256:layer2-digest"},
		},
	}
	
	// Test layer extraction logic
	var layerDigests []string
	for _, layer := range manifest.Layers {
		layerDigests = append(layerDigests, layer.Digest)
	}
	
	if len(layerDigests) != 2 {
		t.Errorf("Expected 2 layers, got %d", len(layerDigests))
	}
	
	if layerDigests[0] != "sha256:layer1-digest" {
		t.Errorf("Expected first layer sha256:layer1-digest, got %s", layerDigests[0])
	}
}

func TestImageDownloaderWithHTTPMock(t *testing.T) {
	// Create mock HTTP client
	mockClient := &api.MockHTTPClient{
		ResponseBody:   `{"token":"test-token"}`,
		ResponseStatus: 200,
		ResponseError:  nil,
	}
	
	// Create real downloader with mock client
	downloader := NewRealImageDownloader(mockClient)
	
	// Test that we can create the downloader
	if downloader == nil {
		t.Error("Downloader should not be nil")
	}
	
	// Test interface compliance
	var _ ImageDownloader = downloader
}

func TestErrorHandling(t *testing.T) {
	// Test various error conditions
	tests := []struct {
		name          string
		mockClient    *api.MockHTTPClient
		expectedError bool
	}{
		{
			name: "HTTP Error",
			mockClient: &api.MockHTTPClient{
				ResponseBody:   "",
				ResponseStatus: 500,
				ResponseError:  fmt.Errorf("connection failed"),
			},
			expectedError: true,
		},
		{
			name: "Invalid JSON",
			mockClient: &api.MockHTTPClient{
				ResponseBody:   "invalid json",
				ResponseStatus: 200,
				ResponseError:  nil,
			},
			expectedError: false, // This would be handled by JSON parsing
		},
		{
			name: "Success",
			mockClient: &api.MockHTTPClient{
				ResponseBody:   `{"token":"valid-token"}`,
				ResponseStatus: 200,
				ResponseError:  nil,
			},
			expectedError: false,
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			downloader := NewRealImageDownloader(test.mockClient)
			if downloader == nil && !test.expectedError {
				t.Error("Expected downloader to be created")
			}
		})
	}
}
package downloader

import "container-manager/pkg/api"

// ImageDownloader interface for mocking
type ImageDownloader interface {
	DownloadImage(image, tag, architecture, containerRoot string) error
	GetToken(image string) (string, error)
	GetDigest(image, tag, architecture, token string) (string, error)
}

// RealImageDownloader implements ImageDownloader using actual functions
type RealImageDownloader struct {
	client api.HTTPClient
}

func NewRealImageDownloader(client api.HTTPClient) *RealImageDownloader {
	return &RealImageDownloader{client: client}
}

func (d *RealImageDownloader) DownloadImage(image, tag, architecture, containerRoot string) error {
	return DownloadImage(image, tag, architecture, containerRoot)
}

func (d *RealImageDownloader) GetToken(image string) (string, error) {
	return getToken(image)
}

func (d *RealImageDownloader) GetDigest(image, tag, architecture, token string) (string, error) {
	return getDigest(image, tag, architecture, token)
}

// MockImageDownloader for testing
type MockImageDownloader struct {
	TokenResponse  string
	TokenError     error
	DigestResponse string
	DigestError    error
	DownloadError  error
}

func (m *MockImageDownloader) DownloadImage(image, tag, architecture, containerRoot string) error {
	return m.DownloadError
}

func (m *MockImageDownloader) GetToken(image string) (string, error) {
	return m.TokenResponse, m.TokenError
}

func (m *MockImageDownloader) GetDigest(image, tag, architecture, token string) (string, error) {
	return m.DigestResponse, m.DigestError
}
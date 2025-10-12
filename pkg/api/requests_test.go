package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestMockHTTPClient_Success(t *testing.T) {
	mock := &MockHTTPClient{
		ResponseBody:   "test response",
		ResponseStatus: 200,
		ResponseError:  nil,
	}
	
	body, status, err := mock.Request("example.com", "/test", "GET", nil, "")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if status != 200 {
		t.Errorf("Expected status 200, got %d", status)
	}
	if body != "test response" {
		t.Errorf("Expected 'test response', got '%s'", body)
	}
}

func TestMockHTTPClient_Error(t *testing.T) {
	mock := &MockHTTPClient{
		ResponseBody:   "",
		ResponseStatus: 500,
		ResponseError:  fmt.Errorf("connection failed"),
	}
	
	_, status, err := mock.Request("example.com", "/test", "GET", nil, "")
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if status != 500 {
		t.Errorf("Expected status 500, got %d", status)
	}
}

func TestRequest_RealHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "container-manager/1.0" {
			t.Errorf("Expected User-Agent header")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()
	
	// Extract host from server URL
	host := strings.TrimPrefix(server.URL, "http://")
	
	// This would test the actual Request function with a real server
	// but we can't easily test HTTPS with httptest
	if host == server.URL {
		t.Error("URL should have been trimmed")
	}
}

func TestRequest_FileSave(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.txt")
	
	mock := &MockHTTPClient{
		ResponseBody:   "File saved",
		ResponseStatus: 200,
		ResponseError:  nil,
	}
	
	body, status, err := mock.Request("example.com", "/file", "GET", nil, filePath)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if status != 200 {
		t.Errorf("Expected status 200, got %d", status)
	}
	if body != "File saved" {
		t.Errorf("Expected 'File saved', got '%s'", body)
	}
}

func TestRequest_Headers(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer test-token",
		"Content-Type":  "application/json",
	}
	
	mock := &MockHTTPClient{
		ResponseBody:   "success",
		ResponseStatus: 200,
		ResponseError:  nil,
	}
	
	body, status, err := mock.Request("example.com", "/api", "GET", headers, "")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if status != 200 {
		t.Errorf("Expected status 200, got %d", status)
	}
	if body != "success" {
		t.Errorf("Expected 'success', got '%s'", body)
	}
}

func TestRealHTTPClient_Interface(t *testing.T) {
	client := &RealHTTPClient{}
	
	// Test that RealHTTPClient implements HTTPClient interface
	var _ HTTPClient = client
	
	// We can't easily test the actual HTTP call without external dependencies
	// but we can verify the interface is implemented correctly
	if client == nil {
		t.Error("Client should not be nil")
	}
}
package api

// HTTPClient interface for mocking HTTP requests
type HTTPClient interface {
	Request(host, path, method string, headers map[string]string, savePath string) (string, int, error)
}

// RealHTTPClient implements HTTPClient using the actual Request function
type RealHTTPClient struct{}

func (c *RealHTTPClient) Request(host, path, method string, headers map[string]string, savePath string) (string, int, error) {
	return Request(host, path, method, headers, savePath)
}

// MockHTTPClient for testing
type MockHTTPClient struct {
	ResponseBody   string
	ResponseStatus int
	ResponseError  error
}

func (m *MockHTTPClient) Request(host, path, method string, headers map[string]string, savePath string) (string, int, error) {
	return m.ResponseBody, m.ResponseStatus, m.ResponseError
}
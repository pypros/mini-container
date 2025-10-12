package api

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
)

func Request(host, path, method string, headers map[string]string, savePath string) (string, int, error) {
	maxRedirects := 5
	redirectCount := 0
	currentURL := fmt.Sprintf("https://%s%s", host, path)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for redirectCount < maxRedirects {
		req, err := http.NewRequest(method, currentURL, nil)
		if err != nil {
			return "", 0, err
		}

		req.Header.Set("User-Agent", "container-manager/1.0")
		for k, v := range headers {
			if redirectCount > 0 && k == "Authorization" {
				continue
			}
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", 0, err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				return "", resp.StatusCode, fmt.Errorf("redirect without location")
			}
			currentURL = location
			redirectCount++
			continue
		}

		if resp.StatusCode == 200 {
			if savePath != "" {
				file, err := os.Create(savePath)
				if err != nil {
					return "", resp.StatusCode, err
				}
				defer file.Close()
				_, err = io.Copy(file, resp.Body)
				return "File saved", resp.StatusCode, err
			}

			body, err := io.ReadAll(resp.Body)
			return string(body), resp.StatusCode, err
		}

		body, _ := io.ReadAll(resp.Body)
		return string(body), resp.StatusCode, nil
	}

	return "", 0, fmt.Errorf("max redirects reached")
}

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	HttpClient *http.Client
	retries    int
}

func NewClient(retries int) *Client {
	return &Client{
		HttpClient: &http.Client{Timeout: 30 * time.Second},
		retries:    retries,
	}
}

func (c *Client) GetFileContent(ctx context.Context, repoPath, filename string) ([]byte, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/main/%s", repoPath, filename)
	log.Printf("Fetching file: %s", url)

	var body []byte
	var lastErr error

	for attempt := 0; attempt <= c.retries; attempt++ {
		if ctx.Err() != nil {
			log.Printf("Context error: %v", ctx.Err())
			return nil, ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("User-Agent", "Go-http-client/1.1")

		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		resp, err := c.HttpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			log.Printf("Attempt %d/%d failed: %v", attempt+1, c.retries+1, lastErr)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			log.Printf("Attempt %d/%d: %v", attempt+1, c.retries+1, lastErr)
			continue
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			log.Printf("Attempt %d/%d: %v", attempt+1, c.retries+1, lastErr)
			continue
		}

		return body, nil
	}

	return nil, fmt.Errorf("failed after %d retries: %v", c.retries+1, lastErr)
}

func (c *Client) ListJSONFiles(ctx context.Context, repoPath string) ([]string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/contents/", repoPath)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Go-http-client/1.1")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var files []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}

	jsonFiles := make([]string, 0)
	for _, file := range files {
		if file.Type == "file" && strings.HasSuffix(file.Name, ".json") {
			jsonFiles = append(jsonFiles, file.Name)
		}
	}

	return jsonFiles, nil
}

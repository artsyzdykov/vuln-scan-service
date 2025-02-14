package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/artsyzdykov/vuln-scan-service/internal/github"
	"github.com/stretchr/testify/assert"
)

func TestGitHubClient_GetFileContent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test content"))
	}))
	defer ts.Close()

	client := github.NewClient(3)
	content, err := client.GetFileContent(context.Background(), "test/repo", "file.json")

	assert.NoError(t, err)
	assert.Equal(t, []byte("test content"), content)
}

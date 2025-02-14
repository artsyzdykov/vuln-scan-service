package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/artsyzdykov/vuln-scan-service/internal/github"
	"github.com/artsyzdykov/vuln-scan-service/internal/handlers"
	"github.com/artsyzdykov/vuln-scan-service/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockStorage struct {
	mock.Mock
}

func (m *MockStorage) SaveVulnerability(ctx context.Context, vuln models.Vulnerability) error {
	args := m.Called(ctx, vuln)
	return args.Error(0)
}

func (m *MockStorage) QueryBySeverity(ctx context.Context, severity string) ([]models.Vulnerability, error) {
	args := m.Called(ctx, severity)
	return args.Get(0).([]models.Vulnerability), args.Error(1)
}

func (m *MockStorage) Close() {
	m.Called()
}

func TestScanHandler(t *testing.T) {

	mockStore := new(MockStorage)
	mockStore.On("SaveVulnerability", mock.Anything, mock.Anything).Return(nil)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{
            "scanResults": {
                "scan_id": "test_scan",
                "resource_type": "container",
                "resource_name": "test_container",
                "vulnerabilities": [{
                    "id": "CVE-TEST",
                    "severity": "HIGH",
                    "cvss": 8.5,
                    "status": "active",
                    "package_name": "test_package",
                    "current_version": "1.0.0",
                    "fixed_version": "1.0.1",
                    "description": "Test vulnerability",
                    "published_date": "2025-01-01T00:00:00Z",
                    "link": "https://example.com",
                    "risk_factors": ["Test Risk"]
                }]
            }
        }]`))
	}))
	defer ts.Close()

	ghClient := github.NewClient(2)
	ghClient.HttpClient = ts.Client()

	router := gin.Default()
	router.POST("/scan", handlers.ScanHandler(mockStore, ghClient))

	reqBody := `{
        "repo": "test/repo",
        "files": ["test.json"]
    }`

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/scan", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.JSONEq(t, `{"status":"accepted","message":"scan started"}`, w.Body.String())

	mockStore.AssertCalled(t, "SaveVulnerability", mock.Anything, mock.MatchedBy(func(v models.Vulnerability) bool {
		return v.ID == "CVE-TEST" && v.Severity == "HIGH"
	}))
}

func TestScanHandler_InvalidRequest(t *testing.T) {
	mockStore := new(MockStorage)
	ghClient := github.NewClient(2)

	router := gin.Default()
	router.POST("/scan", handlers.ScanHandler(mockStore, ghClient))

	reqBody := `{
        "files": ["test.json"]
    }`

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/scan", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "error")
}

func TestScanHandler_GitHubError(t *testing.T) {
	mockStore := new(MockStorage)
	ghClient := github.NewClient(2)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	ghClient.HttpClient = ts.Client()

	router := gin.Default()
	router.POST("/scan", handlers.ScanHandler(mockStore, ghClient))

	reqBody := `{
        "repo": "test/repo",
        "files": ["test.json"]
    }`

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/scan", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	mockStore.AssertNotCalled(t, "SaveVulnerability", mock.Anything, mock.Anything)
}

func TestScanHandler_InvalidJSON(t *testing.T) {
	mockStore := new(MockStorage)
	ghClient := github.NewClient(2)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`invalid json`))
	}))
	defer ts.Close()

	ghClient.HttpClient = ts.Client()

	router := gin.Default()
	router.POST("/scan", handlers.ScanHandler(mockStore, ghClient))

	reqBody := `{
        "repo": "test/repo",
        "files": ["test.json"]
    }`

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/scan", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	mockStore.AssertNotCalled(t, "SaveVulnerability", mock.Anything, mock.Anything)
}

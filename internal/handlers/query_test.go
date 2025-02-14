package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/artsyzdykov/vuln-scan-service/internal/handlers"
	"github.com/artsyzdykov/vuln-scan-service/internal/models"
	"github.com/artsyzdykov/vuln-scan-service/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestQueryHandler(t *testing.T) {
	mockStore := new(storage.MockStorage)
	mockStore.On("QueryBySeverity", mock.Anything, "HIGH").Return([]models.Vulnerability{
		{ID: "CVE-TEST", Severity: "HIGH"},
	}, nil)

	router := gin.Default()
	router.POST("/query", handlers.QueryHandler(mockStore))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/query", strings.NewReader(`{
        "filters": {"severity": "HIGH"}
    }`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "CVE-TEST")

	mockStore.AssertCalled(t, "QueryBySeverity", mock.Anything, "HIGH")
}

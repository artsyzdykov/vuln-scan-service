package handlers

import (
	"github.com/artsyzdykov/vuln-scan-service/internal/storage"
	"github.com/gin-gonic/gin"
	"net/http"
)

type QueryRequest struct {
	Filters struct {
		Severity string `json:"severity" binding:"required,oneof=CRITICAL HIGH MEDIUM LOW"`
	} `json:"filters" binding:"required"`
}

func QueryHandler(store storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req QueryRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		vulns, err := store.QueryBySeverity(c.Request.Context(), req.Filters.Severity)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
			return
		}

		c.JSON(http.StatusOK, vulns)
	}
}

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/artsyzdykov/vuln-scan-service/internal/github"
	"github.com/artsyzdykov/vuln-scan-service/internal/models"
	"github.com/artsyzdykov/vuln-scan-service/internal/storage"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"sync"
	"time"
)

type ScanRequest struct {
	Repo string `json:"repo" binding:"required"`
}

func ScanHandler(store storage.Storage, ghClient *github.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ScanRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx := context.Background()

		files, err := ghClient.ListJSONFiles(ctx, req.Repo)
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to list files"})
			return
		}

		go processScanRequest(ctx, req.Repo, files, store, ghClient)

		c.JSON(202, gin.H{
			"status":  "accepted",
			"message": "scan started",
		})
	}
}

func processScanRequest(parentCtx context.Context, repo string, files []string, store storage.Storage, ghClient *github.Client) {
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)

	for _, filename := range files {
		select {
		case <-ctx.Done():
			log.Printf("Scan canceled: %v", ctx.Err())
			return
		default:
		}

		wg.Add(1)

		go func(f string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			content, err := ghClient.GetFileContent(ctx, repo, f)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					log.Printf("Canceled processing %s", f)
				} else {
					log.Printf("Error fetching %s: %v", f, err)
				}
				return
			}

			var scanResultWrappers []models.ScanResultWrapper
			if err := json.Unmarshal(content, &scanResultWrappers); err != nil {
				log.Printf("Error parsing %s: %v", f, err)
				return
			}

			for _, wrapper := range scanResultWrappers {
				scanResult := wrapper.ScanResults
				for _, vuln := range scanResult.Vulnerabilities {
					vuln.SourceFile = f
					vuln.ScanTime = time.Now().UTC()
					vuln.ResourceType = scanResult.ResourceType
					vuln.ResourceName = scanResult.ResourceName
					vuln.ScanID = scanResult.ScanID

					if err := store.SaveVulnerability(ctx, vuln); err != nil {
						log.Printf("Error saving %s: %v", vuln.ID, err)
					}
				}
			}
		}(filename)
	}

	wg.Wait()
}

package main

import (
	"context"
	"github.com/artsyzdykov/vuln-scan-service/internal/config"
	"github.com/artsyzdykov/vuln-scan-service/internal/github"
	"github.com/artsyzdykov/vuln-scan-service/internal/handlers"
	"github.com/artsyzdykov/vuln-scan-service/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"log"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Config load
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Storage initialization
	store, err := storage.NewPostgresStore(context.Background(), cfg)
	if err != nil {
		log.Fatalf("Failed to init storage: %v", err)
	}
	defer store.Close()

	//Running migrations
	if err := storage.RunMigrations(cfg); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	//GitHub client initialization
	ghClient := github.NewClient(3)

	// Router setup
	router := gin.Default()
	setupRoutes(router, store, ghClient)

	// Running server
	log.Printf("Starting server on port %s", cfg.ServerPort)
	if err := router.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func setupRoutes(router *gin.Engine, store storage.Storage, ghClient *github.Client) {
	router.POST("/scan", handlers.ScanHandler(store, ghClient))

	router.POST("/query", handlers.QueryHandler(store))
}

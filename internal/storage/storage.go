package storage

import (
	"context"
	"github.com/artsyzdykov/vuln-scan-service/internal/models"
)

type Storage interface {
	SaveVulnerability(ctx context.Context, vuln models.Vulnerability) error
	QueryBySeverity(ctx context.Context, severity string) ([]models.Vulnerability, error)
	Close()
}

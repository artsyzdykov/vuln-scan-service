package storage

import (
	"context"
	"github.com/artsyzdykov/vuln-scan-service/internal/models"
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

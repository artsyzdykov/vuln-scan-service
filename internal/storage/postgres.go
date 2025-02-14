package storage

import (
	"context"
	"fmt"
	"github.com/artsyzdykov/vuln-scan-service/internal/config"
	"github.com/artsyzdykov/vuln-scan-service/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(ctx context.Context, cfg *config.Config) (*PostgresStore, error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)

	log.Printf("Connecting to PostgreSQL with DSN: %s", connString)

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	return &PostgresStore{pool: pool}, nil
}

func (store *PostgresStore) Close() {
	store.pool.Close()
}

func (s *PostgresStore) SaveVulnerability(ctx context.Context, vuln models.Vulnerability) error {
	_, err := s.pool.Exec(ctx, `
        INSERT INTO vulnerabilities 
        (id, severity, cvss, status, package_name, current_version, fixed_version,
         description, published_date, link, risk_factors, source_file, scan_time,
         resource_type, resource_name, scan_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        ON CONFLICT (id) DO UPDATE SET
            severity = EXCLUDED.severity,
            cvss = EXCLUDED.cvss,
            status = EXCLUDED.status`,
		vuln.ID, vuln.Severity, vuln.CVSS, vuln.Status, vuln.PackageName,
		vuln.CurrentVersion, vuln.FixedVersion, vuln.Description, vuln.PublishedDate,
		vuln.Link, vuln.RiskFactors, vuln.SourceFile, vuln.ScanTime,
		vuln.ResourceType, vuln.ResourceName, vuln.ScanID)

	return err
}

func (s *PostgresStore) QueryBySeverity(ctx context.Context, severity string) ([]models.Vulnerability, error) {
	rows, err := s.pool.Query(ctx, `
        SELECT 
            id, severity, cvss, status, package_name, 
            current_version, fixed_version, description, 
            published_date, link, risk_factors, 
            source_file, scan_time, resource_type, 
            resource_name, scan_id
        FROM vulnerabilities 
        WHERE severity = $1`,
		severity,
	)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var vuln models.Vulnerability
		err := rows.Scan(
			&vuln.ID, &vuln.Severity, &vuln.CVSS, &vuln.Status,
			&vuln.PackageName, &vuln.CurrentVersion, &vuln.FixedVersion,
			&vuln.Description, &vuln.PublishedDate, &vuln.Link,
			&vuln.RiskFactors, &vuln.SourceFile, &vuln.ScanTime,
			&vuln.ResourceType, &vuln.ResourceName, &vuln.ScanID,
		)
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

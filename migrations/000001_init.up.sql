CREATE TABLE IF NOT EXISTS vulnerabilities (
                                               id VARCHAR(255) PRIMARY KEY,
                                               severity VARCHAR(50) NOT NULL,
                                               cvss FLOAT,
                                               status VARCHAR(50),
                                               package_name VARCHAR(255),
                                               current_version VARCHAR(255),
                                               fixed_version VARCHAR(255),
                                               description TEXT,
                                               published_date TIMESTAMP,
                                               link TEXT,
                                               risk_factors JSONB,
                                               source_file TEXT NOT NULL,
                                               scan_time TIMESTAMP NOT NULL,
                                                resource_type VARCHAR(255),
                                               resource_name VARCHAR(255),
                                               scan_id VARCHAR(255)
);

CREATE INDEX idx_severity ON vulnerabilities(severity);
CREATE INDEX idx_scan_id ON vulnerabilities(scan_id);
# Vulnerability Scan Service

A microservice for scanning GitHub repositories for vulnerability reports and managing scan results.

## 🚀 Key Features

- **Repository Scanning**: Automatic discovery and processing of JSON files
- **Data Storage**: PostgreSQL storage with metadata tracking
- **Vulnerability Querying**: Filter results by severity level
- **Parallel Processing**: Concurrent handling of ≥3 files simultaneously

## ⚡ Quick Start

### Prerequisites

- Docker
- Docker Compose (optional)

### Run in Docker

```bash
# Build image
docker build -t vuln-scan .

# Run container (works with public repositories)
docker run -p 8080:8080 vuln-scan
```

## 🌌 API Endpoints

### 1. Initiate Scan

```bash
POST /scan
{
    "repo": "velancio/vulnerability_scans"
}
```

**Sample Response:**

```json
{
    "status": "accepted",
    "message": "scan started for 5 files"
}
```

### 2. Query Vulnerabilities

```bash
POST /query
{
    "filters": {
        "severity": "HIGH"
    }
}
```

**Sample Response:**

```json
[
    {
        "id": "CVE-2024-1234",
        "severity": "HIGH",
        "package_name": "openssl",
        "current_version": "1.1.1t-r0",
        "fixed_version": "1.1.1u-r0",
        "source_file": "vulnscan1011.json"
    }
]
```

## 🛠 Technical Details

### Architecture

- **Language**: Go 1.21
- **Database**: PostgreSQL 15
- **Web Framework**: Gin
- **Concurrency**: Goroutines + Semaphore pattern
- **Migrations**: golang-migrate

### Implementation Highlights

- Automatic JSON file discovery
- GitHub API retry mechanism (3 attempts)
- Static compilation for Alpine Linux
- Integrated database migrations
- Single-container deployment

## 🤾🏻 Testing

```bash
# Unit tests
go test -v ./...

# Manual testing
curl -X POST http://localhost:8080/scan -d '{"repo":"velancio/vulnerability_scans"}'
curl -X POST http://localhost:8080/query -d '{"filters":{"severity":"HIGH"}}'
```

## 📂 Project Structure

```
vuln-scan/
├── cmd/              # Main application
├── internal/         # Core components
│   ├── config/      # Configuration
│   ├── github/      # Github Client
│   ├── handlers/    # API handlers
│   ├── models/      # Data models
│   └── storage/     # Database layer
├── migrations/      # SQL migrations
├── .env               # Enviroment variables
├── dockerfile         # Docker setup
└── docker-entrypoint.sh # Startup script
```


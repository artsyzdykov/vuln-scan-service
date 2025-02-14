FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git postgresql-client

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /vuln-scan ./cmd/main.go

FROM alpine:latest

RUN apk add --no-cache postgresql postgresql-contrib postgresql-client su-exec
RUN mkdir -p /var/lib/postgresql/data && chown postgres:postgres /var/lib/postgresql/data

COPY --from=builder /vuln-scan /vuln-scan
COPY --from=builder /app/migrations /migrations
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8080
CMD ["docker-entrypoint.sh"]
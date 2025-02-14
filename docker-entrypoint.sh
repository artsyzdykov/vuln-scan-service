#!/bin/sh

set -e

mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql
chmod 775 /run/postgresql

if [ ! -d "/var/lib/postgresql/data/base" ]; then
    echo "Initializing PostgreSQL database..."
    su-exec postgres initdb -D /var/lib/postgresql/data
fi

echo "Starting PostgreSQL..."
su-exec postgres postgres -D /var/lib/postgresql/data &

sleep 5

echo "Checking for existing database..."
su-exec postgres psql -U postgres -tc "SELECT 1 FROM pg_database WHERE datname = 'vulnscan'" | grep -q 1 || su-exec postgres psql -U postgres -c "CREATE DATABASE vulnscan;"

echo "Applying migrations..."
if [ -f /vuln-scan ]; then
    /vuln-scan migrate
fi

echo "Starting vulnerability scan service..."
exec /vuln-scan
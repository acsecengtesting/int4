#!/bin/bash
# Provision a fresh Ubuntu VM for eBPF SQLi detection on PostgreSQL
# Run as root on the target VM
set -e

echo "=== Installing PostgreSQL + eBPF toolchain ==="
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 2; done

apt-get update -qq
apt-get install -y -qq postgresql postgresql-client \
    clang llvm gcc make libbpf-dev linux-tools-common linux-tools-generic \
    libelf-dev zlib1g-dev bpftrace 2>&1 | tail -5

echo ""
echo "=== Starting PostgreSQL ==="
systemctl start postgresql
systemctl enable postgresql

echo ""
echo "=== Setting up test database ==="
sudo -u postgres psql -c "CREATE USER testuser WITH PASSWORD 'testpass';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE testdb OWNER testuser;" 2>/dev/null || true
sudo -u postgres psql -d testdb -c "
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100),
    email VARCHAR(200),
    password_hash VARCHAR(200),
    role VARCHAR(50)
);
INSERT INTO users (username, email, password_hash, role) VALUES
    ('admin', 'admin@example.com', 'hash_admin_123', 'admin'),
    ('alice', 'alice@example.com', 'hash_alice_456', 'user'),
    ('bob', 'bob@example.com', 'hash_bob_789', 'user'),
    ('charlie', 'charlie@example.com', 'hash_charlie_012', 'user')
ON CONFLICT DO NOTHING;
GRANT ALL ON users TO testuser;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO testuser;
"

echo ""
echo "=== Allow TCP connections ==="
PG_HBA=$(find /etc/postgresql -name "pg_hba.conf" | head -1)
echo "host all all 127.0.0.1/32 md5" >> $PG_HBA
PG_CONF=$(find /etc/postgresql -name "postgresql.conf" | head -1)
grep -q "^listen_addresses" $PG_CONF || echo "listen_addresses = 'localhost'" >> $PG_CONF
systemctl reload postgresql

echo ""
echo "=== Checking PostgreSQL binary ==="
PG_BIN=$(find /usr/lib/postgresql -name "postgres" -type f | head -1)
echo "PostgreSQL binary: $PG_BIN"
nm -D $PG_BIN 2>/dev/null | grep -E "exec_simple_query|pg_parse_query" | head -5

echo ""
echo "=== Create project dir ==="
mkdir -p /root/sqli_detect

echo ""
echo "=== Create project dir ==="
mkdir -p /root/sqli_detect

echo ""
echo "=== Versions ==="
psql --version
clang --version | head -1
echo "=== Provision done ==="

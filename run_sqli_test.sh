#!/bin/bash
# Test the eBPF SQL injection detector against PostgreSQL
# Run on the VM after build
set -e

cd /root/sqli_detect

PG_BIN=$(find /usr/lib/postgresql -name "postgres" -type f | head -1)

echo "=== Starting SQLi detector ==="
./sqli_detect "$PG_BIN" > /tmp/sqli_out.log 2>&1 &
DPID=$!
sleep 2

# Verify it's running
if ! kill -0 $DPID 2>/dev/null; then
    echo "ERROR: detector failed to start"
    cat /tmp/sqli_out.log
    exit 1
fi
echo "Detector running (PID $DPID)"

echo ""
echo "=== Test 1: Normal query (should NOT alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT * FROM users WHERE username = 'alice';" 2>&1 | tail -3

echo ""
echo "=== Test 2: UNION-based injection (SHOULD alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT * FROM users WHERE username = '' UNION SELECT 1,version(),3,4,5--'" 2>&1 | tail -3

echo ""
echo "=== Test 3: OR 1=1 injection (SHOULD alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT * FROM users WHERE username = '' OR 1=1--" 2>&1 | tail -3

echo ""
echo "=== Test 4: Stacked query injection (SHOULD alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT 1; DROP TABLE IF EXISTS pwned;" 2>&1 | tail -3

echo ""
echo "=== Test 5: Time-based blind injection (SHOULD alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT * FROM users WHERE username = '' OR pg_sleep(5)--" 2>&1 | tail -3

sleep 2
kill $DPID 2>/dev/null || true
wait $DPID 2>/dev/null || true

echo ""
echo "=== DETECTOR OUTPUT ==="
cat /tmp/sqli_out.log

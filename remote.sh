#!/bin/bash
cd /root/sqli_detect

echo "=== Building ==="
make clean && make 2>&1 | tail -5
echo "Build OK"

echo ""
echo "=== Starting detector ==="
./sqli_detect > /tmp/sqli_out.log 2>&1 &
DPID=$!
sleep 2

echo "=== Test 1: Normal query (should NOT alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT * FROM users WHERE username = 'alice';"

echo ""
echo "=== Test 2: UNION-based injection (SHOULD alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT * FROM users WHERE username = '' UNION SELECT 1,version(),3,4,5--'"

echo ""
echo "=== Test 3: OR 1=1 injection (SHOULD alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT * FROM users WHERE username = '' OR 1=1--"

echo ""
echo "=== Test 4: Stacked query injection (SHOULD alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT 1; DROP TABLE IF EXISTS pwned;"

echo ""
echo "=== Test 5: Time-based blind injection (SHOULD alert) ==="
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb -c "SELECT * FROM users WHERE username = '' OR pg_sleep(5)--"

sleep 2
kill $DPID 2>/dev/null || true
wait $DPID 2>/dev/null || true

echo ""
echo "=== DETECTOR OUTPUT ==="
cat /tmp/sqli_out.log

#!/bin/bash
# Deploy, build, and test the eBPF SQL injection detector on a remote VM
# Usage: ./deploy.sh <VM_IP>
# Requires: SSH key already authorized on the VM

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <VM_IP>"
    exit 1
fi

VM_IP="$1"
SSH="ssh -o StrictHostKeyChecking=no root@$VM_IP"
SCP="scp -o StrictHostKeyChecking=no"
REMOTE_DIR="/root/sqli_detect"

echo "=== Provisioning VM at $VM_IP ==="
$SCP provision.sh root@$VM_IP:/root/
$SSH "chmod +x /root/provision.sh && /root/provision.sh"

echo ""
echo "=== Uploading source files ==="
$SCP sqli_detect.bpf.c sqli_detect.c Makefile run_sqli_test.sh root@$VM_IP:$REMOTE_DIR/
$SSH "chmod +x $REMOTE_DIR/run_sqli_test.sh"

echo ""
echo "=== Building ==="
$SSH "cd $REMOTE_DIR && make clean && make"

echo ""
echo "=== Deploy complete ==="
echo "To test: ssh root@$VM_IP '/root/sqli_detect/run_sqli_test.sh'"

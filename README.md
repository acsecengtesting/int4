# eBPF PostgreSQL Security Tools

Two eBPF-based security tools that detect and block attacks on PostgreSQL at the kernel level, with zero changes to the database configuration.

## sqli_detect — SQL Injection Detection & Blocking

Attaches a uprobe to `pg_parse_query` and inspects every SQL statement entering the PostgreSQL parser. Pattern-matches for common injection signatures before the query executes.

**Detected patterns:**
- UNION SELECT
- OR 1=1 / OR TRUE
- SQL comments (`--`, `/*`)
- Stacked queries (`;DROP`, `;INSERT`, etc.)
- Time-based blind (pg_sleep)

**Block mode** (`--block`): Uses `bpf_probe_write_user` to null out the query string in postgres process memory. The client receives an "empty query" error and the backend stays alive for future connections.

```
./sqli_detect [--block] [/path/to/postgres]
```

## shell_guard — Reverse Shell Prevention

Monitors `sys_enter_execve` for any process execution originating from a PostgreSQL backend. Catches reverse shells attempted via `COPY ... TO PROGRAM`, `lo_export`, or malicious UDFs.

**Allowlist:** Only binaries under `/usr/lib/postgresql/` and `/usr/bin/pg_*` are permitted. Everything else (shells, curl, nc, python, etc.) triggers an alert.

**Block mode** (`--block`): Sends SIGKILL to the unauthorized child process before it executes. The postgres backend stays alive — only the spawned shell is killed.

```
./shell_guard [--block]
```

## Building

Requires: Linux kernel 5.3+, clang, gcc, libbpf-dev, libelf-dev, bpftool.

```
make
```

This generates `vmlinux.h` from BTF, compiles both BPF programs, and links the userspace loaders.

## Deployment

```bash
# Provision a fresh Ubuntu 24.04 VM with PostgreSQL + eBPF toolchain
./provision.sh

# Run both tools together
./sqli_detect --block &
./shell_guard --block &
```

## Testing

```bash
# SQLi detection (should be blocked)
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb \
  -c "SELECT * FROM users WHERE id = 1 UNION SELECT 1,version(),3,4,5"

# Reverse shell attempt (child process killed)
sudo -u postgres psql -d testdb \
  -c "COPY (SELECT 1) TO PROGRAM '/bin/sh -c whoami';"

# Normal query (unaffected)
PGPASSWORD=testpass psql -h 127.0.0.1 -U testuser -d testdb \
  -c "SELECT * FROM users WHERE username = 'alice';"
```

## How It Works

| Tool | Hook point | Mechanism | Block method |
|------|-----------|-----------|--------------|
| sqli_detect | uprobe on `pg_parse_query` | Reads query text, pattern scan | Nulls query via `bpf_probe_write_user` |
| shell_guard | tracepoint `sys_enter_execve` | Checks parent comm for "postgres" | SIGKILL to child process |

Both tools emit structured events via BPF ring buffers for real-time alerting.

## Notes

- Block mode for `sqli_detect` taints the kernel (expected `bpf_probe_write_user` warning in dmesg).
- The scan window for SQL injection is 128 bytes from query start. Injections buried deep in a query may not be caught.
- `shell_guard` checks both the process and its parent for the "postgres" comm name, covering both direct exec and fork+exec patterns.
- Tested on Ubuntu 24.04 / kernel 6.8 / PostgreSQL 16.

# eBPF SQL Injection Detection

Detect SQL injection attacks using eBPF uprobes on the PostgreSQL server binary combined with client-side network correlation from the Java API container.

## Approach

1. **Database-side uprobe on `exec_simple_query`** — reads the raw SQL text as it arrives at the PostgreSQL query executor. Pattern-matches for injection signatures.
2. **Client-side network correlation** — tracks response sizes per connection from the database port. Anomalous response volumes indicate data exfiltration via UNION-based injection.

## Status

Work in progress.

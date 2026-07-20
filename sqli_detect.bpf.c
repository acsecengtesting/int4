// SPDX-License-Identifier: GPL-2.0
// Detect SQL injection via uprobe on PostgreSQL's pg_parse_query
//
// pg_parse_query(const char *query_string) is called for every SQL statement
// entering the parser. We read the query text and check for injection patterns.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_QUERY_LEN 256

// Suspicious patterns that indicate SQL injection
// We check for these at the kernel level as a first-pass filter
#define PATTERN_UNION_SELECT  1
#define PATTERN_OR_TRUE       2
#define PATTERN_COMMENT       3
#define PATTERN_STACKED       4
#define PATTERN_SLEEP         5

struct sqli_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u64 mnt_ns_inum;
    __u8  pattern_type;
    __u8  _pad[7];
    char  query[MAX_QUERY_LEN];
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sqli_events SEC(".maps");

// Detect SQL injection patterns using a simple bounded scan.
// Linux 6.8 supports bounded loops in BPF, so no need for #pragma unroll.

#define SCAN_LEN 128

static __always_inline char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static __always_inline __u8 detect_pattern(const char *query, int len) {
    int scan = len;
    if (scan > SCAN_LEN)
        scan = SCAN_LEN;

    for (int i = 0; i < scan - 5; i++) {
        char c0 = to_lower(query[i]);
        char c1 = to_lower(query[i+1]);

        // "union"
        if (c0 == 'u' && c1 == 'n' &&
            to_lower(query[i+2]) == 'i' &&
            to_lower(query[i+3]) == 'o' &&
            to_lower(query[i+4]) == 'n')
            return PATTERN_UNION_SELECT;

        // "sleep"
        if (c0 == 's' && c1 == 'l' &&
            to_lower(query[i+2]) == 'e' &&
            to_lower(query[i+3]) == 'e' &&
            to_lower(query[i+4]) == 'p')
            return PATTERN_SLEEP;

        // "or 1=" or "or t" (or true)
        if (c0 == 'o' && c1 == 'r' && query[i+2] == ' ') {
            if (query[i+3] == '1' && query[i+4] == '=')
                return PATTERN_OR_TRUE;
            if (to_lower(query[i+3]) == 't')
                return PATTERN_OR_TRUE;
        }

        // "--"
        if (query[i] == '-' && query[i+1] == '-')
            return PATTERN_COMMENT;

        // "/*"
        if (query[i] == '/' && query[i+1] == '*')
            return PATTERN_COMMENT;

        // Stacked queries: ";" followed by dangerous keyword
        if (query[i] == ';' && i > 3) {
            int j = i + 1;
            if (j < scan && query[j] == ' ') j++;
            if (j < scan && query[j] == ' ') j++;
            if (j + 2 < scan) {
                char s = to_lower(query[j]);
                if (s == 'd' || s == 'i' || s == 'u' || s == 'c')
                    return PATTERN_STACKED;
            }
        }
    }
    return 0;
}

// Uprobe on pg_parse_query(const char *query_string)
// arg0 (%rdi) = query_string pointer
SEC("uprobe")
int BPF_KPROBE(uprobe_pg_parse_query, const char *query_string)
{
    if (!query_string)
        return 0;

    // Read the query string from postgres process memory
    char query[MAX_QUERY_LEN] = {};
    int ret = bpf_probe_read_user_str(query, sizeof(query), query_string);

    // Check for null/empty or error
    if (ret <= 1)
        return 0;

    // ret includes null terminator, so length is ret - 1
    int len = ret - 1;
    if (len > MAX_QUERY_LEN - 1)
        len = MAX_QUERY_LEN - 1;

    // Check for injection patterns
    __u8 pattern = detect_pattern(query, len);
    if (!pattern)
        return 0;

    // SQL injection pattern detected — emit alert
    struct sqli_event *e = bpf_ringbuf_reserve(&sqli_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->pattern_type = pattern;
    __builtin_memset(e->_pad, 0, 7);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->mnt_ns_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    __builtin_memcpy(e->query, query, MAX_QUERY_LEN);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

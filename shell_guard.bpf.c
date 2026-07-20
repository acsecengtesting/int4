// SPDX-License-Identifier: GPL-2.0
// shell_guard: Detect/block unexpected process execution from PostgreSQL backends.
//
// Uses tracepoint/syscalls/sys_enter_execve to intercept exec calls.
// If the calling process (or its parent) is a postgres backend, and the
// binary being exec'd is not on the allowlist, we alert or kill it with SIGKILL.
//
// This prevents reverse shells via COPY ... PROGRAM, lo_export, or malicious UDFs.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 128
#define COMM_LEN 16

// Event emitted when a suspicious exec is detected
struct shell_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  blocked;
    __u8  _pad[3];
    char  parent_comm[COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
    char  comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} shell_events SEC(".maps");

// Configuration: when block_mode is non-zero, send SIGKILL to the process.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} shell_config SEC(".maps");

// Check: is comm == "postgres"?
static __always_inline int is_postgres(const char *comm) {
    return comm[0] == 'p' && comm[1] == 'o' && comm[2] == 's' &&
           comm[3] == 't' && comm[4] == 'g' && comm[5] == 'r' &&
           comm[6] == 'e' && comm[7] == 's' && comm[8] == '\0';
}

// Check if filename is an allowed postgres binary.
// We check for known safe prefixes/patterns without scanning the full path.
static __always_inline int is_allowed(const char *filename) {
    // Allow anything under /usr/lib/postgresql/ (pg helpers live there)
    if (filename[0] == '/' && filename[1] == 'u' && filename[2] == 's' &&
        filename[3] == 'r' && filename[4] == '/' && filename[5] == 'l' &&
        filename[6] == 'i' && filename[7] == 'b' && filename[8] == '/' &&
        filename[9] == 'p' && filename[10] == 'o' && filename[11] == 's' &&
        filename[12] == 't' && filename[13] == 'g' && filename[14] == 'r')
        return 1;

    // Also allow /usr/bin/pg_* (some distros put helpers there)
    if (filename[0] == '/' && filename[1] == 'u' && filename[2] == 's' &&
        filename[3] == 'r' && filename[4] == '/' && filename[5] == 'b' &&
        filename[6] == 'i' && filename[7] == 'n' && filename[8] == '/' &&
        filename[9] == 'p' && filename[10] == 'g')
        return 1;

    return 0;
}

// Tracepoint args for sys_enter_execve
struct exec_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int shell_guard_exec(struct exec_args *ctx)
{
    // Get current process comm
    char comm[COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    // Get parent comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    char parent_comm[COMM_LEN] = {};
    bpf_probe_read_kernel_str(parent_comm, sizeof(parent_comm),
                              BPF_CORE_READ(parent, comm));

    // Only care if current or parent is postgres
    if (!is_postgres(comm) && !is_postgres(parent_comm))
        return 0;

    // Read the filename being exec'd
    char filename[MAX_FILENAME_LEN] = {};
    const char *fname_ptr = ctx->filename;
    bpf_probe_read_user_str(filename, sizeof(filename), fname_ptr);

    // Check if it's an allowed postgres binary
    if (is_allowed(filename))
        return 0;

    // Suspicious exec from postgres context — emit event
    struct shell_event *e = bpf_ringbuf_reserve(&shell_events, sizeof(*e), 0);
    if (!e) {
        // Still block if configured, even without event
        __u32 key = 0;
        __u32 *block = bpf_map_lookup_elem(&shell_config, &key);
        if (block && *block)
            bpf_send_signal(9);  // SIGKILL
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(parent, tgid);
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->blocked = 0;
    __builtin_memset(e->_pad, 0, 3);
    __builtin_memcpy(e->comm, comm, COMM_LEN);
    __builtin_memcpy(e->parent_comm, parent_comm, COMM_LEN);
    __builtin_memcpy(e->filename, filename, MAX_FILENAME_LEN);

    // Check block mode
    __u32 key = 0;
    __u32 *block = bpf_map_lookup_elem(&shell_config, &key);
    if (block && *block) {
        bpf_send_signal(9);  // SIGKILL
        e->blocked = 1;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

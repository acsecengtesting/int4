// SPDX-License-Identifier: GPL-2.0
// Userspace loader for SQL injection detector
// Usage: ./sqli_detect [--block] [postgres_binary_path]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_QUERY_LEN 256

struct sqli_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u64 mnt_ns_inum;
    __u8  pattern_type;
    __u8  blocked;
    __u8  _pad[6];
    char  query[MAX_QUERY_LEN];
    char  comm[16];
};

static volatile int running = 1;
static int block_mode = 0;

static void sig_handler(int sig) { running = 0; }

static const char *pattern_name(__u8 p) {
    switch (p) {
        case 1: return "UNION SELECT";
        case 2: return "OR TRUE/1=1";
        case 3: return "SQL COMMENT (--)";
        case 4: return "STACKED QUERY";
        case 5: return "SLEEP (blind)";
        default: return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct sqli_event *e = data;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char time_buf[32];
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);

    const char *action = e->blocked ? "BLOCKED" : "DETECTED";
    printf("[%s] SQLI %s: %s\n", time_buf, action, pattern_name(e->pattern_type));
    printf("       pid=%d comm=%s mnt_ns=%llu\n",
           e->pid, e->comm, (unsigned long long)e->mnt_ns_inum);
    printf("       query=%.200s\n\n", e->query);
    fflush(stdout);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--block] [postgres_binary_path]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --block   Enable block mode: null out detected SQLi queries\n");
    fprintf(stderr, "            so PostgreSQL returns 'empty query' to the client.\n");
    fprintf(stderr, "            WARNING: uses bpf_probe_write_user (taints kernel).\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  Without --block, operates in detect-only mode (default).\n");
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    const char *pg_bin = "/usr/lib/postgresql/16/bin/postgres";

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--block") == 0) {
            block_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            pg_bin = argv[i];
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("SQL Injection Detector (PostgreSQL uprobe)\n");
    printf("Mode: %s\n", block_mode ? "BLOCK (queries will be nulled)" : "DETECT ONLY");
    printf("PostgreSQL binary: %s\n\n", pg_bin);

    if (block_mode) {
        printf("WARNING: Block mode uses bpf_probe_write_user().\n");
        printf("         This taints the kernel and may print warnings to dmesg.\n\n");
    }

    obj = bpf_object__open_file("sqli_detect.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object failed: %d\n", err);
        goto cleanup;
    }

    // Set block mode in the BPF config map
    int config_fd = bpf_object__find_map_fd_by_name(obj, "sqli_config");
    if (config_fd < 0) {
        fprintf(stderr, "ERROR: finding config map failed\n");
        err = 1;
        goto cleanup;
    }
    __u32 key = 0;
    __u32 value = block_mode ? 1 : 0;
    err = bpf_map_update_elem(config_fd, &key, &value, BPF_ANY);
    if (err) {
        fprintf(stderr, "ERROR: setting block mode in config map: %d\n", err);
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "uprobe_pg_parse_query");
    if (!prog) {
        fprintf(stderr, "ERROR: finding uprobe program failed\n");
        err = 1;
        goto cleanup;
    }

    // Attach uprobe to pg_parse_query in the postgres binary
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
        .func_name = "pg_parse_query",
        .retprobe = false,
    );
    link = bpf_program__attach_uprobe_opts(prog, -1, pg_bin, 0, &uprobe_opts);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: attaching uprobe to pg_parse_query failed\n");
        link = NULL;
        err = 1;
        goto cleanup;
    }

    printf("Attached uprobe to pg_parse_query (monitoring ALL postgres backends)\n");
    printf("Press Ctrl+C to stop.\n\n");

    int map_fd = bpf_object__find_map_fd_by_name(obj, "sqli_events");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding events map failed\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (libbpf_get_error(rb)) {
        fprintf(stderr, "ERROR: creating ring buffer failed\n");
        err = 1;
        goto cleanup;
    }

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ERROR: polling ring buffer: %d\n", err);
            break;
        }
    }

    printf("\nDetaching...\n");

cleanup:
    if (rb) ring_buffer__free(rb);
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    return err != 0;
}

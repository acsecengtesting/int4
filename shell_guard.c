// SPDX-License-Identifier: GPL-2.0
// Userspace loader for shell_guard: PostgreSQL reverse shell prevention
// Usage: ./shell_guard [--block] [--verbose]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_FILENAME_LEN 128
#define COMM_LEN 16

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

static volatile int running = 1;
static int verbose = 0;

static void sig_handler(int sig) { running = 0; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct shell_event *e = data;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char time_buf[32];
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);

    const char *action = e->blocked ? "BLOCKED" : "ALERT";
    printf("[%s] SHELL %s: postgres child exec\n", time_buf, action);
    printf("       pid=%d ppid=%d uid=%d\n", e->pid, e->ppid, e->uid);
    printf("       caller=%s parent=%s\n", e->comm, e->parent_comm);
    printf("       exec=%s\n\n", e->filename);
    fflush(stdout);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--block] [--verbose]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Monitors for unexpected process execution from PostgreSQL backends.\n");
    fprintf(stderr, "Detects reverse shells via COPY ... PROGRAM, lo_export, or UDFs.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --block    Kill unauthorized exec with SIGKILL.\n");
    fprintf(stderr, "  --verbose  Show additional diagnostic output.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Requires kernel 5.3+ (no special config needed).\n");
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    int block_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--block") == 0)
            block_mode = 1;
        else if (strcmp(argv[i], "--verbose") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Shell Guard (PostgreSQL exec monitor)\n");
    printf("Mode: %s\n", block_mode ? "BLOCK (unauthorized exec denied)" : "DETECT ONLY");
    printf("\n");

    obj = bpf_object__open_file("shell_guard.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object failed: %d\n", err);
        goto cleanup;
    }

    // Set block mode in config map
    int config_fd = bpf_object__find_map_fd_by_name(obj, "shell_config");
    if (config_fd < 0) {
        fprintf(stderr, "ERROR: finding shell_config map failed\n");
        err = 1;
        goto cleanup;
    }
    __u32 key = 0;
    __u32 value = block_mode ? 1 : 0;
    err = bpf_map_update_elem(config_fd, &key, &value, BPF_ANY);
    if (err) {
        fprintf(stderr, "ERROR: setting block mode: %d\n", err);
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "shell_guard_exec");
    if (!prog) {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        err = 1;
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: attaching tracepoint program failed\n");
        link = NULL;
        err = 1;
        goto cleanup;
    }

    printf("Attached to tracepoint/syscalls/sys_enter_execve\n");
    printf("Monitoring postgres backends for unauthorized exec.\n");
    printf("Allowed: postgres, pg_* helpers. Everything else triggers alert.\n");
    printf("Press Ctrl+C to stop.\n\n");

    int map_fd = bpf_object__find_map_fd_by_name(obj, "shell_events");
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

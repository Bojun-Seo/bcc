// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 LG Electronics Inc.

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "functrace.h"
#include "functrace.skel.h"
#include "trace_helpers.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define DATETIME_SIZE 32

static struct prog_env {
	pid_t pid;
	unsigned int interval;
	char *file_output;
	char *target;
	char *bin_path;
	char *symbolname;
	bool duration;
	bool verbose;
} env = {
	.interval = 99999999,
	.file_output = NULL,
	.duration = false,
	.verbose = false,
};

const char *argp_program_version = "functrace 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "FUNCTION";
static const char program_doc[] =
"Print start timestamp and duration for the specified function\n"
"\n"
"Usage: functrace [OPTIONS...] -p PID BIN_PATH:FUNCTION\n"
"\n"
"Examples:\n"
"  ./functrace -p 181 /lib/libc.so:read              # trace the read() library function\n"
"  ./functrace -p 181 -o my.log /lib/libc.so:read    # save logs on my.log file\n"
"  ./functrace -p 181 -d /lib/libc.so:read           # change time unit to ns and print duration\n"
;

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "interval", 'i', "INTERVAL", 0, "Quit interval in seconds", 0 },
	{ "output", 'o', "FILE", 0,
	  "Output to FILE instead of standard output", 0 },
	{ "duration", 'd', NULL, 0,
	  "Change time unit to nanosecond and print duration", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	long interval, pid;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env->pid = pid;
		break;
	case 'i':
		errno = 0;
		interval = strtol(arg, NULL, 10);
		if (errno || interval <= 0) {
			warn("Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		env->interval = interval;
		break;
	case 'o':
		env->file_output = strdup(arg);
		break;
	case 'd':
		env->duration = true;
		break;
	case 'v':
		env->verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		if (env->target) {
			warn("Too many arguments: %s\n", arg);
			argp_usage(state);
		}
		env->target = arg;
		break;
	case ARGP_KEY_END:
		if (!env->target) {
			warn("Need a target to trace\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

long long get_boot_time_offset() {
    struct timespec realtime, monotonic;
    if (clock_gettime(CLOCK_REALTIME, &realtime) == -1 || clock_gettime(CLOCK_MONOTONIC, &monotonic) == -1) {
        perror("clock_gettime");
        return -1;
    }
    return (realtime.tv_sec * 1000000000LL + realtime.tv_nsec) - (monotonic.tv_sec * 1000000000LL + monotonic.tv_nsec);
}

static int attach_uprobe_with_offset(struct functrace_bpf *obj, char* bin_path,
				     char* function, off_t func_off)
{
	long err;

	obj->links.dummy_kprobe =
		bpf_program__attach_uprobe(obj->progs.dummy_kprobe, false,
					   env.pid ?: -1, bin_path, func_off);
	if (!obj->links.dummy_kprobe) {
		err = -errno;
		warn("Failed to attach uprobe: %ld\n", err);
		return -2;
	}

	obj->links.dummy_kretprobe =
		bpf_program__attach_uprobe(obj->progs.dummy_kretprobe, true,
					   env.pid ?: -1, bin_path, func_off);
	if (!obj->links.dummy_kretprobe) {
		err = -errno;
		warn("Failed to attach uretprobe: %ld\n", err);
		return -3;
	}

	return 0;

}

static int attach_uprobe(struct functrace_bpf *obj, char* bin_path, char* function)
{
	off_t func_off = get_elf_func_offset(bin_path, function);

	if (func_off < 0) {
		warn("Could not find %s in %s\n", function, bin_path);
		return -1;
	}

	return attach_uprobe_with_offset(obj, bin_path, function, func_off);
}

static void sig_hand(int signr)
{
}

static struct sigaction sigact = {.sa_handler = sig_hand};

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};
	struct syms_cache *syms_cache = NULL;
	struct functrace_bpf *obj;
	int err;
	int fd = -1;
	FILE *os = stdout;
	struct key_t key = {};
	struct key_t next_key;
	struct value_info info;
	pid_t pid;
	pid_t tid;
	struct tm *tm_info;
	char buffer[DATETIME_SIZE];
	long long boot_offset;
	long long epoch_ns;
	time_t epoch_s;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	sigaction(SIGINT, &sigact, 0);
	sigaction(SIGTERM, &sigact, 0);

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = functrace_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	err = functrace_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object\n");
		return 1;
	}

	fd = bpf_map__fd(obj->maps.infos);

	env.bin_path = strdup(env.target);
	if (!env.bin_path) {
		warn("strdup failed");
		return 1;
	}

	env.symbolname = strchr(env.bin_path, ':');
	if (!env.symbolname) {
		warn("Binary should have contained ':' (internal bug!)\n");
		return 1;
	}
	*env.symbolname = '\0';
	env.symbolname++;

	err = attach_uprobe(obj, env.bin_path, env.symbolname);
	if (err)
		goto cleanup;

	err = functrace_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
			strerror(-err));
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to load syms_cache\n");
		goto cleanup;
	}

	boot_offset = get_boot_time_offset();

	printf("Tracing %s.  Hit Ctrl-C to exit\n", env.target);
	if (env.duration)
		printf("Timestamp\tDuration\tpid\ttid\tFunc\tArg\n");
	else
		printf("Timestamp\tpid\ttid\tFunc\tArg\n");

	sleep(env.interval);

	if (env.file_output) {
		os = fopen(env.file_output, "w");
		if (!os) {
			fprintf(stderr, "failed to open file %s\n", env.file_output);
			goto cleanup;
		}
	}

	if (bpf_map_get_next_key(fd, NULL, &next_key) != 0) {
		fprintf(stderr, "no key found in map\n");
		goto cleanup;
	}

	do {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err) {
			fprintf(stderr, "failed to lookup key %d\n", err);
			break;
		}

		pid = next_key.pid_tid >> 32;
		tid = next_key.pid_tid;

		if (env.duration) {
			fprintf(os, "%llu\t%llu", next_key.start_nsec,
				info.end_nsec - next_key.start_nsec);
		} else {
			epoch_ns = boot_offset + next_key.start_nsec;
			epoch_s = epoch_ns / 1000000000LL;
			tm_info = localtime(&epoch_s);
			strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
			fprintf(os, "%s", buffer);
		}
		fprintf(os, "\t%d\t%d\t%s\t%llu\n", pid, tid, env.symbolname, info.data);
		key = next_key;
	} while (bpf_map_get_next_key(fd, &key, &next_key) == 0);

	printf("Exiting trace of %s\n", env.target);

cleanup:
	syms_cache__free(syms_cache);
	functrace_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	free(env.file_output);
	free(env.bin_path);

	return err != 0;
}

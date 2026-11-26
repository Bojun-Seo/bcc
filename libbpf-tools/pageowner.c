// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * pageowner    Show the owners of outstanding page allocations.
 *
 * Like page_owner of the kernel (CONFIG_PAGE_OWNER), this records who
 * allocated each block of pages, i.e. the kernel stack, task, gfp mask, order
 * and time, and reports the blocks that are still allocated. Unlike
 * page_owner, it needs neither a kernel built with CONFIG_PAGE_OWNER nor
 * booting with page_owner=on, but only sees allocations made while it runs.
 *
 * Copyright (c) 2026 LG Electronics
 *
 * 26-Nov-2026   Bojun Seo   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include "pageowner.h"
#include "pageowner.skel.h"
#include "btf_helpers.h"
#include "map_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */
#define OPT_MAX_ALLOCS			3 /* --max-allocs */

#define MAX_GFP_FLAGS			32

static struct env {
	pid_t pid;
	int interval;
	int count;
	int top;
	bool dump;
	int max_allocs;
	int stack_storage_size;
	int perf_max_stack_depth;
	bool verbose;
} env = {
	.interval = 99999999,
	.count = 99999999,
	.top = 10,
	.stack_storage_size = 10240,
	.perf_max_stack_depth = 127,
};

struct stack_stat {
	__s32 stack_id;
	__u64 nr_pages;
	__u64 nr_allocs;
};

static struct gfp_flag {
	char *name;
	__u32 mask;
} gfp_flags[MAX_GFP_FLAGS];
static int nr_gfp_flags;

static const char *migratetype_names[] = {
	"Unmovable", "Movable", "Reclaimable", "HighAtomic",
};

static volatile sig_atomic_t exiting;
static struct ksyms *ksyms;
static unsigned long *ips;
static __u64 *keys;
static struct page_info *vals;
static __u32 *idx;
static long page_kib;

const char *argp_program_version = "pageowner 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show the owners of outstanding page allocations, like page_owner.\n"
"\n"
"USAGE: pageowner [-h] [-v] [-p PID] [-T TOP] [-d] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    pageowner            # summarize outstanding pages by stack on Ctrl-C\n"
"    pageowner 5 3        # summarize every 5 seconds, 3 times\n"
"    pageowner -p 181     # only track pages allocated by PID 181\n"
"    pageowner -T 3       # show the top 3 stacks only\n"
"    pageowner -d         # dump each allocation in page_owner format\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Only track pages allocated by this process", 0 },
	{ "top", 'T', "TOP", 0, "Show only this many top stacks (default 10)", 0 },
	{ "dump", 'd', NULL, 0,
	  "Dump each outstanding allocation like /sys/kernel/debug/page_owner", 0 },
	{ "max-allocs", OPT_MAX_ALLOCS, "MAX-ALLOCS", 0,
	  "the number of outstanding allocations that can be tracked (default "
	  "1048576, or the number of pages in the system if smaller)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 10240)", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for kernel stack traces (default 127)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static int parse_int(const char *arg, const char *what, struct argp_state *state)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(arg, &end, 10);
	if (errno || *end || val <= 0 || val > INT_MAX) {
		warn("invalid %s: %s\n", what, arg);
		argp_usage(state);
	}
	return val;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		env.pid = parse_int(arg, "PID", state);
		break;
	case 'T':
		env.top = parse_int(arg, "top", state);
		break;
	case 'd':
		env.dump = true;
		break;
	case OPT_MAX_ALLOCS:
		env.max_allocs = parse_int(arg, "max allocs", state);
		break;
	case OPT_STACK_STORAGE_SIZE:
		env.stack_storage_size = parse_int(arg, "stack storage size", state);
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = parse_int(arg, "perf max stack depth", state);
		break;
	case ARGP_KEY_ARG:
		if (pos_args == 0) {
			env.interval = parse_int(arg, "interval", state);
		} else if (pos_args == 1) {
			env.count = parse_int(arg, "count", state);
		} else {
			warn("unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
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

static void sig_handler(int sig)
{
	exiting = 1;
}

/*
 * Since v6.9, the gfp flags are defined by an enum of ___GFP_<FLAG>_BIT, so
 * their names can be read from BTF. Only the mask is shown on older kernels,
 * where the bit of each flag depends on the kernel version and config.
 */
static int load_gfp_flags(void)
{
	const struct btf_type *t;
	const struct btf_enum *e;
	const char *name;
	struct btf *btf;
	__u32 id, nr_types;
	int i, len, err = 0;

	btf = btf__load_vmlinux_btf();
	if (!btf)
		return 0;

	nr_types = btf__type_cnt(btf);
	for (id = 1; id < nr_types && !nr_gfp_flags; id++) {
		t = btf__type_by_id(btf, id);
		if (!btf_is_enum(t))
			continue;
		e = btf_enum(t);
		for (i = 0; i < btf_vlen(t) && nr_gfp_flags < MAX_GFP_FLAGS; i++) {
			name = btf__name_by_offset(btf, e[i].name_off);
			len = name ? strlen(name) : 0;
			if (len < 12 || strncmp(name, "___GFP_", 7) ||
			    strcmp(name + len - 4, "_BIT") ||
			    !strcmp(name, "___GFP_LAST_BIT") ||
			    !strcmp(name, "___GFP_UNUSED_BIT") ||
			    e[i].val < 0 || e[i].val >= 32)
				continue;
			/* ___GFP_<FLAG>_BIT -> __GFP_<FLAG> */
			gfp_flags[nr_gfp_flags].name = strndup(name + 1, len - 5);
			if (!gfp_flags[nr_gfp_flags].name) {
				err = -ENOMEM;
				goto out;
			}
			gfp_flags[nr_gfp_flags++].mask = 1U << e[i].val;
		}
	}
out:
	btf__free(btf);
	return err;
}

static void free_gfp_flags(void)
{
	int i;

	for (i = 0; i < nr_gfp_flags; i++)
		free(gfp_flags[i].name);
}

static void print_gfp_flags(__u32 gfp)
{
	const char *sep = "(";
	int i;

	if (!nr_gfp_flags || !gfp)
		return;
	for (i = 0; i < nr_gfp_flags; i++) {
		if (!(gfp & gfp_flags[i].mask))
			continue;
		printf("%s%s", sep, gfp_flags[i].name);
		gfp &= ~gfp_flags[i].mask;
		sep = "|";
	}
	if (gfp)
		printf("%s%#x", sep, gfp);
	printf(")");
}

static const char *migratetype_name(int migratetype)
{
	if (migratetype < 0 || migratetype >= (int)ARRAY_SIZE(migratetype_names))
		return "Unknown";
	return migratetype_names[migratetype];
}

static void print_stack(int fd, __s32 stack_id, const char *indent)
{
	const struct ksym *ksym;
	int i;

	if (stack_id < 0 || bpf_map_lookup_elem(fd, &stack_id, ips)) {
		printf("%s[Missed Kernel Stack]\n", indent);
		return;
	}
	for (i = 0; i < env.perf_max_stack_depth && ips[i]; i++) {
		ksym = ksyms__map_addr(ksyms, ips[i]);
		if (ksym)
			printf("%s%s+0x%lx\n", indent, ksym->name, ips[i] - ksym->addr);
		else
			printf("%s0x%lx\n", indent, ips[i]);
	}
}

static __s32 stack_key(const struct page_info *info)
{
	/* put all the allocations without a stack trace together */
	return info->stack_id < 0 ? -1 : info->stack_id;
}

/* sort by stack, and by allocation within the same stack */
static int cmp_info(const void *a, const void *b)
{
	const struct page_info *x = a, *y = b;

	if (stack_key(x) != stack_key(y))
		return stack_key(x) < stack_key(y) ? -1 : 1;
	if (x->ts != y->ts)
		return x->ts < y->ts ? -1 : 1;
	if (x->pid != y->pid)
		return x->pid < y->pid ? -1 : 1;
	return 0;
}

/* sort by the number of pages, the most first */
static int cmp_stat(const void *a, const void *b)
{
	const struct stack_stat *x = a, *y = b;

	if (x->nr_pages != y->nr_pages)
		return x->nr_pages > y->nr_pages ? -1 : 1;
	if (x->nr_allocs != y->nr_allocs)
		return x->nr_allocs > y->nr_allocs ? -1 : 1;
	return x->stack_id < y->stack_id ? -1 : x->stack_id > y->stack_id;
}

static int cmp_pfn(const void *a, const void *b)
{
	__u64 x = keys[*(const __u32 *)a], y = keys[*(const __u32 *)b];

	return x < y ? -1 : x > y;
}

static int print_summary(int stack_fd, __u32 nr)
{
	__u64 total_pages = 0, total_allocs = 0;
	const struct page_info *info, *prev = NULL;
	struct stack_stat *stats, *stat = NULL;
	__u32 i, nr_stats = 0;
	char ts[32];

	stats = calloc(nr ? nr : 1, sizeof(*stats));
	if (!stats) {
		warn("failed to allocate memory\n");
		return -1;
	}

	qsort(vals, nr, sizeof(*vals), cmp_info);
	for (i = 0; i < nr; i++) {
		info = &vals[i];
		if (!stat || stat->stack_id != stack_key(info)) {
			stat = &stats[nr_stats++];
			stat->stack_id = stack_key(info);
			prev = NULL;
		}
		stat->nr_pages += 1ULL << info->order;
		/* the blocks split from an allocation share its time and pid */
		if (!prev || prev->ts != info->ts || prev->pid != info->pid)
			stat->nr_allocs++;
		prev = info;
	}
	qsort(stats, nr_stats, sizeof(*stats), cmp_stat);

	str_timestamp("%H:%M:%S", ts, sizeof(ts));
	printf("[%s] Top %u stacks with outstanding pages:\n", ts,
	       nr_stats < (__u32)env.top ? nr_stats : (__u32)env.top);
	for (i = 0; i < nr_stats; i++) {
		total_pages += stats[i].nr_pages;
		total_allocs += stats[i].nr_allocs;
		if (i >= (__u32)env.top)
			continue;
		printf("\n%llu pages (%llu KiB) in %llu allocations from stack\n",
		       (unsigned long long)stats[i].nr_pages,
		       (unsigned long long)stats[i].nr_pages * page_kib,
		       (unsigned long long)stats[i].nr_allocs);
		print_stack(stack_fd, stats[i].stack_id, "\t");
	}
	printf("\nTotal: %llu pages (%llu KiB) in %llu allocations\n\n",
	       (unsigned long long)total_pages,
	       (unsigned long long)total_pages * page_kib,
	       (unsigned long long)total_allocs);

	free(stats);
	return 0;
}

/* print in the format of /sys/kernel/debug/page_owner, ordered by PFN */
static void print_dump(int stack_fd, __u32 nr)
{
	const struct page_info *info;
	__u32 i;

	for (i = 0; i < nr; i++)
		idx[i] = i;
	qsort(idx, nr, sizeof(*idx), cmp_pfn);

	for (i = 0; i < nr; i++) {
		info = &vals[idx[i]];
		printf("Page allocated via order %u, mask %#x", info->order,
		       info->gfp_flags);
		print_gfp_flags(info->gfp_flags);
		printf(", pid %u, tgid %u (%s), ts %llu ns\n", info->pid,
		       info->tgid, info->comm, (unsigned long long)info->ts);
		printf("PFN 0x%llx type %s\n", (unsigned long long)keys[idx[i]],
		       migratetype_name(info->migratetype));
		print_stack(stack_fd, info->stack_id, " ");
		printf("\n");
	}
}

/*
 * The kernel skips a BPF program if another one is running on the same CPU,
 * e.g. when a page is freed from an interrupt that arrived while one of our
 * programs was running.
 */
static __u64 prog_misses(const struct bpf_program *prog)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	if (bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &len))
		return 0;
	return info.recursion_misses;
}

static int print_report(struct pageowner_bpf *obj, int pages_fd, int stack_fd)
{
	__u64 invalid_key = -1, nr_untracked, nr_lost_allocs, nr_lost_frees;
	__u32 i, nr = env.max_allocs, nr_no_stack = 0;
	int err = 0;

	/* the PFN of a failed allocation, -1, is never used as a key */
	if (dump_hash(pages_fd, keys, sizeof(*keys), vals, sizeof(*vals), &nr,
		      &invalid_key, false)) {
		warn("failed to read the pages map: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < nr; i++)
		nr_no_stack += vals[i].stack_id < 0;

	if (env.dump)
		print_dump(stack_fd, nr);
	else
		err = print_summary(stack_fd, nr);
	fflush(stdout);

	nr_untracked = obj->bss->nr_untracked;
	if (nr_untracked)
		warn("WARNING: %llu allocations could not be tracked, "
		     "consider increasing --max-allocs\n",
		     (unsigned long long)nr_untracked);
	if (nr_no_stack)
		warn("WARNING: %u allocations have no stack trace, "
		     "consider increasing --stack-storage-size\n", nr_no_stack);
	nr_lost_allocs = prog_misses(obj->progs.handle_page_alloc);
	if (nr_lost_allocs)
		warn("WARNING: missed %llu page allocations\n",
		     (unsigned long long)nr_lost_allocs);
	nr_lost_frees = prog_misses(obj->progs.handle_page_free);
	if (nr_lost_frees)
		warn("WARNING: missed %llu page frees, "
		     "some pages may be wrongly reported as outstanding\n",
		     (unsigned long long)nr_lost_frees);
	return err;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct pageowner_bpf *obj = NULL;
	int pages_fd, stack_fd;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	page_kib = sysconf(_SC_PAGESIZE) / 1024;
	/* each tracked block has its own PFN, so there can't be more of them */
	if (!env.max_allocs) {
		long nr_pages = sysconf(_SC_PHYS_PAGES);

		env.max_allocs = nr_pages > 0 && nr_pages < MAX_ALLOCS ?
				 nr_pages : MAX_ALLOCS;
	}

	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = pageowner_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->target_tgid = env.pid;
	obj->rodata->self_tgid = getpid();

	bpf_map__set_max_entries(obj->maps.pages, env.max_allocs);
	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = pageowner_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	keys = calloc(env.max_allocs, sizeof(*keys));
	vals = calloc(env.max_allocs, sizeof(*vals));
	idx = calloc(env.max_allocs, sizeof(*idx));
	ips = calloc(env.perf_max_stack_depth, sizeof(*ips));
	if (!keys || !vals || !idx || !ips) {
		warn("failed to allocate memory\n");
		err = 1;
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warn("failed to load kallsyms\n");
		err = 1;
		goto cleanup;
	}

	if (env.dump) {
		err = load_gfp_flags();
		if (err) {
			warn("failed to load gfp flags: %s\n", strerror(-err));
			goto cleanup;
		}
	}

	err = pageowner_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* keep the dump free of anything but allocations */
	fprintf(env.dump ? stderr : stdout,
		"Tracing page allocations... Hit Ctrl-C to end.\n");

	pages_fd = bpf_map__fd(obj->maps.pages);
	stack_fd = bpf_map__fd(obj->maps.stackmap);
	if (pages_fd < 0 || stack_fd < 0) {
		warn("failed to get map fds\n");
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(env.interval);

		err = print_report(obj, pages_fd, stack_fd);
		if (err || exiting || --env.count == 0)
			break;
	}

cleanup:
	pageowner_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	ksyms__free(ksyms);
	free_gfp_flags();
	free(keys);
	free(vals);
	free(idx);
	free(ips);

	return err != 0;
}

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 LG Electronics Inc.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "functrace.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, struct value_info);
} infos SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} start SEC(".maps");

static void entry(struct pt_regs *ctx)
{
	u64 nsec = bpf_ktime_get_ns();
	u64 pid_tid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&start, &pid_tid, &nsec, BPF_ANY);
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{
	entry(ctx);
	return 0;
}

static void exit()
{
	struct key_t key;
	struct value_info info;
	u64 time = bpf_ktime_get_ns();
	u64 pid_tid = bpf_get_current_pid_tgid();

	u64* start_nsec = bpf_map_lookup_elem(&start, &pid_tid);
	if (!start_nsec)
		return;

	key.start_nsec = *start_nsec;
	key.pid_tid = pid_tid;
	info.end_nsec = time;
	info.data = 0;

	bpf_map_update_elem(&infos, &key, &info, BPF_ANY);
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
	exit();
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

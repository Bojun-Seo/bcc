// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Copyright (c) 2026 LG Electronics
 *
 * 26-Nov-2026   Bojun Seo   Created this.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"
#include "pageowner.h"

/*
 * Upper bound of the number of page orders, only used to bound loops. The
 * running kernel's number of orders is read from BTF by nr_page_orders().
 */
#define MAX_NR_ORDERS		16

const volatile pid_t target_tgid = 0;
const volatile pid_t self_tgid = 0;
const volatile bool combined_only = false;

/* page blocks that could not be tracked because the pages map was full */
__u64 nr_untracked = 0;

/* the value size is reduced with -C, so it has no BTF type */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ALLOCS);
	__uint(key_size, sizeof(u64));	/* PFN of the first page of the block */
	__uint(value_size, sizeof(struct page_info));
} pages SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);		/* resized with -C */
	__type(key, s32);		/* stack id */
	__type(value, struct stack_count);
} stack_counts SEC(".maps");

/* NR_PAGE_ORDERS, or MAX_ORDER before v6.8: zone->free_area[] has one each */
static __always_inline u32 nr_page_orders(void)
{
	u32 sz = bpf_core_type_size(struct free_area);

	if (sz && bpf_core_field_exists(struct zone, free_area))
		return bpf_core_field_size(struct zone, free_area) / sz;
	return MAX_NR_ORDERS;
}

/* with -C, keep the number of outstanding pages and blocks per stack trace */
static __always_inline void count_pages(s32 stack_id, s64 nr_pages, s64 nr_blocks)
{
	struct stack_count *cnt, zero = {};

	if (!combined_only)
		return;
	cnt = bpf_map_lookup_or_try_init(&stack_counts, &stack_id, &zero);
	if (!cnt)
		return;
	__sync_fetch_and_add(&cnt->nr_pages, nr_pages);
	__sync_fetch_and_add(&cnt->nr_blocks, nr_blocks);
}

SEC("tracepoint/kmem/mm_page_alloc")
int handle_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u64 pfn = ctx->pfn;
	struct page_info info = {}, *stale;
	int err;

	/* the allocation failed */
	if (pfn == -1UL)
		return 0;
	if (target_tgid && target_tgid != (u32)(id >> 32))
		return 0;
	/* the memory pageowner itself uses to report is not interesting */
	if (self_tgid == (u32)(id >> 32))
		return 0;

	info.stack_id = bpf_get_stackid(ctx, &stackmap, 0);
	info.order = ctx->order;
	if (!combined_only) {
		info.migratetype = ctx->migratetype;
		info.ts = bpf_ktime_get_ns();
		info.pid = (u32)id;
		info.tgid = id >> 32;
		info.gfp_flags = ctx->gfp_flags;
		bpf_get_current_comm(&info.comm, sizeof(info.comm));
	}

	err = bpf_map_update_elem(&pages, &pfn, &info,
				  combined_only ? BPF_NOEXIST : BPF_ANY);
	if (err == -EEXIST) {
		/* the free of the previous block at this PFN was missed */
		stale = bpf_map_lookup_elem(&pages, &pfn);
		if (stale)
			count_pages(stale->stack_id, -(1LL << stale->order), -1);
		err = bpf_map_update_elem(&pages, &pfn, &info, BPF_ANY);
	}
	if (err) {
		__sync_fetch_and_add(&nr_untracked, 1);
		return 0;
	}
	count_pages(info.stack_id, 1LL << info.order, 1);
	return 0;
}

SEC("tracepoint/kmem/mm_page_free")
int handle_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	u32 order = ctx->order, nr_orders = nr_page_orders(), o = order, i;
	u64 pfn = ctx->pfn, head = pfn, buddy;
	struct page_info *infop = NULL, info;
	s64 nr_pages, nr_blocks = -1;

	/*
	 * An allocation is usually freed as a whole, but once it is split, e.g.
	 * by split_page() or when a THP is split, its parts are freed one by
	 * one. As buddy allocations are naturally aligned, the allocation that
	 * contains the freed block starts at its PFN aligned down to the order
	 * of the allocation, so look for it from the freed order upwards.
	 */
	for (i = 0; i < MAX_NR_ORDERS && o < nr_orders; i++, o++) {
		head = pfn & ~((1ULL << o) - 1);
		infop = bpf_map_lookup_elem(&pages, &head);
		if (infop)
			break;
	}
	if (!infop)
		return 0;
	/* a smaller block found above the freed order does not contain it */
	if (o > order && infop->order < o)
		return 0;

	if (combined_only)
		__builtin_memcpy(&info, infop, offsetof(struct page_info, ts));
	else
		info = *infop;
	/* someone else is freeing another part of the same allocation */
	if (bpf_map_delete_elem(&pages, &head))
		return 0;
	/* the freed block may be larger than the tracked one, e.g. after a missed free */
	nr_pages = -(1LL << (info.order < order ? info.order : order));

	/*
	 * If only a part was freed, keep tracking the rest of the allocation as
	 * buddy blocks of decreasing order, like expand() of the page allocator.
	 */
	for (i = 0; i < MAX_NR_ORDERS && info.order > order; i++) {
		info.order--;
		buddy = (pfn & ~((1ULL << info.order) - 1)) ^ (1ULL << info.order);
		if (bpf_map_update_elem(&pages, &buddy, &info, BPF_ANY)) {
			__sync_fetch_and_add(&nr_untracked, 1);
			nr_pages -= 1LL << info.order;
		} else {
			nr_blocks++;
		}
	}
	count_pages(info.stack_id, nr_pages, nr_blocks);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

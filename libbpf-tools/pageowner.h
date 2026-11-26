/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PAGEOWNER_H
#define __PAGEOWNER_H

#define TASK_COMM_LEN		16
#define MAX_ALLOCS		(1 << 20)

/*
 * Owner of a block of 2^order pages starting at the PFN used as the map key,
 * recorded when the block was allocated.
 */
struct page_info {
	__u64 ts;		/* allocation time, ns since boot */
	__u32 pid;
	__u32 tgid;
	__u32 gfp_flags;
	__s32 stack_id;		/* kernel stack trace, < 0 if missing */
	__u16 order;
	__s16 migratetype;
	char comm[TASK_COMM_LEN];
};

#endif /* __PAGEOWNER_H */

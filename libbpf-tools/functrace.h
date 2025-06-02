// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 LG Electronics Inc.

#pragma once

#define MAX_ENTRIES 10240

struct key_t {
	__u64 start_nsec;
	__u64 pid_tid; // higher 32-bit: pid, lower 32-bit: tid
};

struct value_info {
	__u64 end_nsec;
	__u64 data; // can be used for various purpose(e.g. func arg)
};

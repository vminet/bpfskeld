#pragma once

#include <limits.h>

#define BPF_STRV_SHIFT 12
#define BPF_STRV_SIZE  (1UL << BPF_STRV_SHIFT)
#define BPF_STRV_MASK  (BPF_STRV_SIZE - 1)

struct bpf_strv
{
	unsigned long size;
	char buf[BPF_STRV_SIZE];
};

struct exec_event
{
	pid_t pid;
	uid_t uid, euid;
	uid_t gid, egid;

	char interp[PATH_MAX];
	char filename[PATH_MAX];

	int argc, envc;
	struct bpf_strv args, env;
};

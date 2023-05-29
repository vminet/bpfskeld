#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace-exec-event.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1UL << 19);
} events SEC(".maps");

static int bpf_copy_strv (struct bpf_strv *strv, long start, long end)
{
	int ret;

	strv->size = (end - start) & BPF_STRV_MASK;

	ret = bpf_probe_read_user(strv->buf, strv->size, (void *)start);
	strv->buf[BPF_STRV_SIZE - 1] = '\0';
	return ret;
}

static void copy_credentials (struct exec_event *ev, struct cred *cred)
{
	ev->uid  = cred->uid.val;
	ev->gid  = cred->gid.val;
	ev->euid = cred->euid.val;
	ev->egid = cred->egid.val;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(trace_process_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	int ret;
	struct exec_event *ev;
	struct mm_struct *mm = p->mm;

	ev = bpf_ringbuf_reserve(&events, sizeof *ev, 0);
	if (!ev)
		return 0;

	ev->pid = old_pid;
	copy_credentials(ev, bprm->cred);

	ret = bpf_core_read_str(&ev->interp, sizeof ev->interp, bprm->interp);
	if (ret < 0)
		goto error;

	ret = bpf_core_read_str(&ev->filename, sizeof ev->filename, bprm->filename);
	if (ret < 0)
		goto error;

	ev->argc = bprm->argc;
	ev->envc = bprm->envc;

	ret = bpf_copy_strv(&ev->args, mm->arg_start, mm->arg_end);
	if (ret < 0)
		goto error;

	ret = bpf_copy_strv(&ev->env, mm->env_start, mm->env_end);
	if (ret < 0)
		goto error;

	bpf_ringbuf_submit(ev, BPF_RB_FORCE_WAKEUP);
	return 0;

error:
	bpf_ringbuf_discard(ev, BPF_RB_NO_WAKEUP);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

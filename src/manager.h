#pragma once

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "bpf/trace-exec-skel.h"

struct manager
{
	sd_bus *bus;
	sd_event *event;
	sd_event_source *bpfev;

	struct ring_buffer *ring;
	struct trace_exec_bpf *bpf;

	unsigned long exec_cnt;
};

extern int manager_new (struct manager **m);
extern void manager_freep (struct manager **m);

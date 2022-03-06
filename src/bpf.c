#include <stddef.h>
#include "bpf.h"
#include "bus.h"
#include "utils.h"
#include "bpf/trace-exec-skel.h"
#include "bpf/trace-exec-event.h"

static int handle_event (void *ctx, void *data, size_t data_sz)
{
	struct manager *m = ctx;
	const struct exec_event *ev = data;

	m->exec_cnt++;
	bus_signal_process_exec(m, ev);

	return 0;
}

static int handle_io (sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	int ret;
	struct manager *m = userdata;

	ret = ring_buffer__poll(m->ring, 0);
	return ret < 0 ? ret : 0;
}

int manager_load_bpf (struct manager *m)
{
	int ret;
	int epfd;
	int mapfd;

	m->bpf = trace_exec_bpf__open_and_load();
	if (!m->bpf)
		return log_error_errno(0, "failed to open BPF skeleton\n");

	ret = trace_exec_bpf__attach(m->bpf);
	if (ret)
		return log_error_errno(ret, "failed to attach BPF skeleton\n");

	mapfd = bpf_map__fd(m->bpf->maps.events);

	m->ring = ring_buffer__new(mapfd, handle_event, m, NULL);
	if (!m->ring)
		return log_error_errno(ret, "failed to create BPF ring buffer\n");

	epfd = ring_buffer__epoll_fd(m->ring);

	ret = sd_event_add_io(m->event, &m->bpfev, epfd, EPOLLIN, handle_io, m);
	if (ret < 0)
		return log_error_errno(ret, "failed to setup BPF I/O handler: %m\n");

	return 0;
}

void manager_free_bpf (struct manager *m)
{
	sd_event_source_disable_unref(m->bpfev);
	ring_buffer__free(m->ring);
	trace_exec_bpf__destroy(m->bpf);
}

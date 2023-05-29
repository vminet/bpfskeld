#include <errno.h>
#include <stdlib.h>
#include "bus.h"
#include "bpf.h"
#include "utils.h"
#include "manager.h"

int manager_new (struct manager **ptr, const char *btf_vmlinux)
{
	int ret;
	__cleanup(manager_freep) struct manager *m = NULL;

	m = calloc(sizeof *m, 1);
	if (!m)
		return log_error_errno(ENOMEM, "failed to allocate manager: %m\n");

	m->btf_vmlinux = btf_vmlinux;

	ret = sd_event_default(&m->event);
	if (ret < 0)
		log_error_errno(ret, "failed to allocate event loop: %m\n");

	ret = sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);
	if (ret < 0)
		return log_error_errno(ret, "failed to setup SIGINT handler: %m\n");

	ret = sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
	if (ret < 0)
		return log_error_errno(ret, "failed to setup SIGTERM handler: %m\n");

	ret = sd_event_set_watchdog(m->event, 1);
	if (ret < 0)
		return log_error_errno(ret, "failed to setup watchdog: %m\n");

	ret = manager_connect_bus(m);
	if (ret < 0)
		return ret;

	ret = manager_load_bpf(m);
	if (ret < 0)
		return ret;

	*ptr = take_ptr(m);
	return 0;
}

void manager_freep (struct manager **ptr)
{
	struct manager *m = *ptr;

	if (m == NULL)
		return;

	manager_free_bpf(m);
	sd_bus_flush_close_unref(m->bus);
	sd_event_unref(m->event);
	free(m);
}

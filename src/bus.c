#include <stddef.h>
#include <systemd/sd-bus.h>
#include "bus.h"
#include "utils.h"

#include <unistd.h>

#define DBUS_PATH      "/com/example/bpfskeld1"
#define DBUS_INTERFACE "com.example.bpfskeld1"

static const sd_bus_vtable manager_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("ExecCount", "t", NULL, offsetof(struct manager, exec_cnt), 0),
	SD_BUS_SIGNAL_WITH_ARGS("ProcessExecEvent",
		SD_BUS_ARGS("i", pid, "i", uid, "i", euid, "i", gid, "i", egid, "s", interp, "s", filename,
		            "i", argc, "as", argv, "i", envc, "as", env), 0),
	SD_BUS_VTABLE_END,
};

static int bus_message_append_strv (sd_bus_message *m, const struct bpf_strv *strv)
{
	int ret;
	const char *ptr = strv->buf;
	const char *end = strv->buf + strv->size;

	ret = sd_bus_message_open_container(m, 'a', "s");
	if (ret < 0)
		return ret;

	while (ptr < end) {
		ret = sd_bus_message_append_basic(m, 's', ptr);
		if (ret < 0)
			return ret;

		ptr += strlen(ptr) + 1;
	}

	return sd_bus_message_close_container(m);
}

int bus_signal_process_exec (struct manager *m, const struct exec_event *ev)
{
	int ret;
	__cleanup(sd_bus_message_unrefp) sd_bus_message *msg = NULL;

	ret = sd_bus_message_new_signal(m->bus, &msg, DBUS_PATH, DBUS_INTERFACE, "ProcessExecEvent");
	if (ret < 0)
		return ret;

	ret = sd_bus_message_append_basic(msg, 'i', &ev->pid);
	if (ret < 0)
		return ret;

	ret = sd_bus_message_append(msg, "iiii", ev->uid, ev->euid, ev->gid, ev->egid);
	if (ret < 0)
		return ret;

	ret = sd_bus_message_append_basic(msg, 's', ev->interp);
	if (ret < 0)
		return ret;

	ret = sd_bus_message_append_basic(msg, 's', ev->filename);
	if (ret < 0)
		return ret;

	ret = sd_bus_message_append_basic(msg, 'i', &ev->argc);
	if (ret < 0)
		return ret;

	ret = bus_message_append_strv(msg, &ev->args);
	if (ret < 0)
		return ret;

	ret = sd_bus_message_append_basic(msg, 'i', &ev->envc);
	if (ret < 0)
		return ret;

	ret = bus_message_append_strv(msg, &ev->env);
	if (ret < 0)
		return ret;

	return sd_bus_send(m->bus, msg, NULL);
}

int manager_connect_bus (struct manager *m)
{
	int ret;

	ret = sd_bus_open_system(&m->bus);
	if (ret < 0)
		return log_error_errno(ret, "failed to connect to system bus: %m\n");

	ret = sd_bus_add_object_vtable(m->bus, NULL, DBUS_PATH, DBUS_INTERFACE, manager_vtable, m);
	if (ret < 0)
		return log_error_errno(ret, "failed to add dbus vtable: %m\n");

	ret = sd_bus_request_name(m->bus, DBUS_INTERFACE, 0);
	if (ret < 0)
		return log_error_errno(ret, "failed to request dbus service name: %m\n");

	ret = sd_bus_attach_event(m->bus, m->event, SD_EVENT_PRIORITY_NORMAL);
	if (ret < 0)
		return log_error_errno(ret, "failed to attach dbus to event loop: %m\n");

	return 0;
}

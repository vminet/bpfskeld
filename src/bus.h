#pragma once

#include "manager.h"
#include "bpf/trace-exec-event.h"

extern int manager_connect_bus (struct manager *m);
extern int bus_signal_process_exec (struct manager *m, const struct exec_event *ev);

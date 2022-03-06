#pragma once

#include "manager.h"

extern int manager_load_bpf (struct manager *m);
extern void manager_free_bpf (struct manager *m);

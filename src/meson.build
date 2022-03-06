bpfskeld_sources = files(
  'bpf.c',
  'bus.c',
  'manager.c',
  'main.c',
  'utils.c',
)

subdir('bpf')
bpfskeld_sources += trace_exec_skel_h

executable(
  'bpfskeld',
  bpfskeld_sources,
  dependencies : [libbpf, libsystemd],
  install : true,
)

# bpftool_gen_skel - generate a BPF skeleton C header file
bpftool_gen_skel = [bpftool, 'gen', 'skeleton', '@INPUT@']

# llvm_strip_debug - strip DWARF information from an object
llvm_strip_debug = [llvm_strip, '--strip-debug', '@INPUT@', '-o', '@OUTPUT@']

# bpftool_btf_dump - dump btf records in c format
bpftool_btf_dump = [bpftool, 'btf', 'dump', 'file', '@INPUT@', 'format', 'c']

# vmlinux.h
vmlinux_h = custom_target(
  'vmlinux.h',
  input : get_option('vmlinux'),
  output : 'vmlinux.h',
  capture : true,
  command : bpftool_btf_dump,
)

# clang_compile_bpf - compile a BPF target
clang_bpf_flags = [
  '-target',
  'bpf',
  '-O2',
  '-g',
  '-c',
  '-Wno-compare-distinct-pointer-types',
]

clang_arch_flag = '-D__@0@__'.format(host_machine.cpu_family())
multiarch = run_command(clang, '--print-multiarch', check : true).stdout().strip()

clang_bpf_includes = [
  '-I.',
  '-include', vmlinux_h,
  '-idirafter', libbpf.get_variable('includedir'),
  '-idirafter', '/usr/include/@0@'.format(multiarch), # hack for Debian/Ubuntu
]

clang_compile_bpf = [
  clang,
  clang_bpf_flags,
  clang_arch_flag,
  clang_bpf_includes,
  '@INPUT@',
  '--output',
  '@OUTPUT@',
]

# trace-exec.bpf.unstripped.o
trace_exec_bpf_unstripped_o = custom_target(
  'trace-exec.bpf.unstripped.o',
  input : 'trace-exec.bpf.c',
  output : 'trace-exec.bpf.unstripped.o',
  command : clang_compile_bpf,
)

# trace-exec.bpf.o
trace_exec_bpf_o = custom_target(
  'trace-exec.bpf.o',
  input : trace_exec_bpf_unstripped_o,
  output : 'trace-exec.bpf.o',
  command : llvm_strip_debug,
)

# trace-exec-skel.h
trace_exec_skel_h = custom_target(
  'trace-exec-skel.h',
  input : trace_exec_bpf_o,
  output : 'trace-exec-skel.h',
  capture : true,
  command : bpftool_gen_skel,
)

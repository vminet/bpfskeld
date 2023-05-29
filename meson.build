project(
  'bpfskeld',
  'c',
  version : '0.1',
  license : 'LGPLv2+',
  default_options : [
    'c_std=gnu99',
    'prefix=/usr',
    'warning_level=2',
  ]
)

# Dependencies
libsystemd = dependency('libsystemd', version : '>= 218')
libbpf     = dependency('libbpf', version : '>= 1.0.0')
clang      = find_program('clang', version : '>= 13.0.0')
llvm_strip = find_program('llvm-strip', version : '>= 13.0.0')
bpftool    = find_program('bpftool', version : '>= 5.2.0')

# Global configuration
conf = configuration_data()
conf.set('_GNU_SOURCE', true)
conf.set('PROJECT_VERSION', meson.project_version())

config_h = configure_file(output : 'config.h', configuration : conf)
add_project_arguments('-include', 'config.h', language : 'c')

# Compiler and Linker flags
cc_flags = [
  '-Wno-unused-parameter',
  '-fvisibility=hidden',
  '-fno-strict-aliasing',
  '-fstack-protector-strong',
  '--param=ssp-buffer-size=4',
]

ld_flags = [
  '-Wl,-z,relro',
  '-Wl,-z,now',
  '-fstack-protector-strong',
]

if get_option('buildtype') != 'debug'
  cc_flags += [
    '-fdata-sections',
    '-ffunction-sections',
  ]

  ld_flags += [
    '-Wl,--gc-sections'
  ]
endif

cc = meson.get_compiler('c')
add_project_arguments(cc.get_supported_arguments(cc_flags), language : 'c')
add_project_link_arguments(cc.get_supported_link_arguments(ld_flags), language : 'c')

# Include sub-directories
subdir('src')

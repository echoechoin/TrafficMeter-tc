clang = find_program('clang')

# Determine BPF target architecture define from host CPU
arch = host_machine.cpu_family()
if arch == 'x86_64'
  bpf_arch_define = '-D__TARGET_ARCH_x86'
  bpf_sys_inc = '/usr/include/x86_64-linux-gnu'
elif arch == 'aarch64'
  bpf_arch_define = '-D__TARGET_ARCH_arm64'
  bpf_sys_inc = '/usr/include/aarch64-linux-gnu'
else
  bpf_arch_define = '-D__TARGET_ARCH_' + arch
  bpf_sys_inc = '/usr/include'
endif

traffic_meter_bpf = custom_target('traffic_meter_bpf',
  input  : 'traffic_meter.c',
  output : 'traffic_meter.bpf.o',
  command : [
    clang,
    '-O2', '-g',
    '-target', 'bpf',
    '-I' + meson.project_source_root() / 'include',
    '-I' + meson.current_source_dir(),
    '-isystem', bpf_sys_inc,
    bpf_arch_define,
    '-c', '@INPUT@',
    '-o', '@OUTPUT@',
  ],
  build_by_default : true,
)

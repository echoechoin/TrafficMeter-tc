libbpf_dep = dependency('libbpf')
jsonc_dep  = dependency('json-c')

traffic_meter_exe = executable('traffic_meter',
  'traffic_meter.c',
  'traffic_meter_cmd.c',
  include_directories : inc,
  dependencies : [libbpf_dep, jsonc_dep],
  install : true,
)

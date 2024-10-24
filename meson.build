project('exec-from-memory', 'c', default_options: ['c_std=c99'])

fs = import('fs')
cmake = import('cmake')

conf = configuration_data()

payload_path = get_option('payload')

if payload_path == ''
    error('-Dpayload not specified')
endif

if not fs.is_absolute(payload_path)
    payload_path = join_paths(meson.project_source_root(), payload_path)
endif

if get_option('mlock_or_die')
    conf.set('mlock_or_die', 1)
else
    conf.set('mlock_or_die', 0)
endif

pack_args = [
    './pack.py',
    '--input', payload_path,
    '--outdir', '.',
    '--key', get_option('aes_key'),
]

pack_out = ['payload.c', 'payload.h']
packed = custom_target(
    command: pack_args,
    output: pack_out,
    build_always_stale: true,
    build_by_default: true,
)

deps = []
cflags = ['-fno-stack-protector']
ldflags = ['-static']

tinyaes_proj = cmake.subproject('tinyaes')
tinyaes_dep = tinyaes_proj.dependency('tiny-aes')
deps += [tinyaes_dep]

cvector_proj = cmake.subproject('cvector')
cvector_dep = cvector_proj.dependency('c-vector')
deps += [cvector_dep]

configure_file(input: 'config.h.in', output: 'config.h', configuration: conf)

executable(
    'executor',
    ['main.c', 'execve.c', 'execve.h', 'exec_jmp.s', packed],
    dependencies: deps,
    c_args: cflags,
    link_args: ldflags,
)
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

opt_debugg = get_option('debugg')

conf.set('INTERP', get_option('interp'))
conf.set('DEBUGG', opt_debugg)

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
cflags = [
    '-fno-stack-protector', '-masm=intel', '-Wall', '-Wextra', '-Wundef',
    '-Wshadow', '-Wpointer-arith', '-Wcast-align', '-Wstrict-overflow=5',
    '-Wwrite-strings', '-Waggregate-return', '-Wcast-qual', '-Wswitch-enum',
    '-Wunreachable-code', '-Wno-unused-parameter'
]
ldflags = ['-static']

if opt_debugg
    cflags += ['-fverbose-asm', '-fsanitize=undefined']
    ldflags += ['-fsanitize=undefined']
endif

tinyaes_proj = cmake.subproject('tinyaes')
tinyaes_dep = tinyaes_proj.dependency('tiny-aes')
deps += [tinyaes_dep]

cvector_proj = cmake.subproject('cvector')
cvector_dep = cvector_proj.dependency('c-vector')
deps += [cvector_dep]

configure_file(input: 'config.h.in', output: 'config.h', configuration: conf)

executable(
    'executor',
    ['main.c', 'execve.c', 'execve.h', packed],
    dependencies: deps,
    c_args: cflags,
    link_args: ldflags,
)
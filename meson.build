project('exec-from-memory', 'c', default_options: ['c_std=c99'], meson_version: '>=1.3.0')

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

conf.set('INTERP_OVERRIDE', get_option('interp'))
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
cflags = [
    '-fno-stack-protector', '-masm=intel', '-Wall', '-Wextra', '-Wundef',
    '-Wshadow', '-Wpointer-arith', '-Wcast-align', '-Wstrict-overflow=5',
    '-Wwrite-strings', '-Waggregate-return', '-Wcast-qual', '-Wswitch-enum',
    '-Wunreachable-code', '-Wno-unused-parameter'
]
ldflags = ['-static']

if opt_debugg
    cflags += ['-g', '-fverbose-asm']

    # Some runtimes (musl) don't support this sanitizer
    if meson.get_compiler('c').has_define('__GLIBC__')
        cflags += ['-fsanitize=undefined']
        ldflags += ['-fsanitize=undefined']
    endif
endif

tinyaes_proj = cmake.subproject('tinyaes')
tinyaes_dep = tinyaes_proj.dependency('tiny-aes')

cvector_proj = cmake.subproject('cvector')
cvector_dep = cvector_proj.dependency('c-vector')

unity_proj = subproject('unity')
unity_dep = unity_proj.get_variable('unity_dep')
unity_runner_gen = unity_proj.get_variable('gen_test_runner')

test_execve = executable('test_execve',
    sources: [
        'execve.c',
        'execve_test.c',
        unity_runner_gen.process(meson.project_source_root() / 'execve_test.c'),
    ],
    dependencies: [unity_dep, cvector_dep],
    c_args: [cflags] + ['-DUNITY_TEST'],
    link_args: ldflags,
    d_unittest: true,
)

test(test_execve.name(), test_execve)

configure_file(input: 'config.h.in', output: 'config.h', configuration: conf)

executable('executor',
    sources: ['main.c', 'execve.c', 'execve.h', packed],
    dependencies: [tinyaes_dep, cvector_dep],
    c_args: cflags,
    link_args: ldflags,
)
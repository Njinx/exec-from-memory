project('exec-from-memory', 'c', default_options: ['c_std=c99'], meson_version: '>=1.3.0')

fs = import('fs')
cmake = import('cmake')

conf = configuration_data()

opt_interp = get_option('interp')
opt_payload_path = get_option('payload')
opt_aes_key = get_option('aes_key')
opt_stack_size = get_option('stack_size')
opt_debugg = get_option('debugg')

if opt_payload_path == ''
    error('-Dpayload not specified')
endif

if opt_aes_key == '11223344556677889900aabbccddeeff'
    warning('Using default AES key')
endif

if opt_stack_size == 0
    error('-Dstack_size must be greater than 0')
elif opt_stack_size != -1
    conf.set('STACK_SIZE', opt_stack_size)
endif

conf.set('INTERP_OVERRIDE', '"@0@"'.format(opt_interp))
conf.set('DEBUGG', opt_debugg)

if not fs.is_absolute(opt_payload_path)
    opt_payload_path = meson.project_source_root() / opt_payload_path
endif

pack_args = [
    './pack.py',
    '--input', opt_payload_path,
    '--outdir', '.',
    '--key', opt_aes_key,
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

test_files_base = ['elf1.bin', 'auxv1.bin', 'auxv2.bin']
test_files = []
foreach test_file : test_files_base
    test_files += ['tests' / 'files' / test_file]
endforeach

foreach test_file : test_files
    fs.copyfile(test_file)
endforeach

configure_file(input: 'config.h.in', output: 'config.h', configuration: conf)

test_execve = executable('test_execve',
    sources: [
        'execve.c',
        'tests' / 'test_utils.c',
        'tests' / 'execve_test.c',
        unity_runner_gen.process(meson.project_source_root() / 'tests' / 'execve_test.c'),
    ],
    dependencies: [unity_dep, cvector_dep],
    c_args: [cflags] + ['-DUNITY_TEST'],
    link_args: ldflags,
    d_unittest: true,
    install: false,
)

test(test_execve.name(), test_execve)

executable('executor',
    sources: ['main.c', 'execve.c', 'execve.h', packed],
    dependencies: [tinyaes_dep, cvector_dep],
    c_args: cflags,
    link_args: ldflags,
)

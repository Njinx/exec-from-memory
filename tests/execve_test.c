#include <sys/mman.h>
#include <stdbool.h>
#include <stdint.h>

#include <unity.h>
#include <cvector.h>

#include "tests/test_utils.h"
#include "execve_internal.h"

void test_append_to_maptable(void);
void test_dup_stack(void);
void helper_test_argenvp(void **stack, char **expected);
void helper_test_auxv(void **stack, char const *auxv_fname);

extern cvector_vector_type(struct mapinfo) maptable;

void test_append_to_maptable(void)
{
    struct mapinfo map1, map2, *curr_map;

    map1 = (struct mapinfo) {
        .ptr = (void *)1234,
        .len = 10,
        .prot = PROT_EXEC,
    };
    map2 = (struct mapinfo) {
        .ptr = (void *)4567,
        .len = 20,
        .prot = PROT_READ | PROT_WRITE,
    };

    append_to_maptable(map1);
    curr_map = cvector_begin(maptable);
    TEST_ASSERT_EQUAL(1, cvector_size(maptable));
    TEST_ASSERT_EQUAL_MEMORY(&map1, curr_map, sizeof(struct mapinfo));

    append_to_maptable(map2);
    curr_map = cvector_begin(maptable); // curr_map may not be the same pointer after append
    ++curr_map;
    TEST_ASSERT_EQUAL(2, cvector_size(maptable));
    TEST_ASSERT_EQUAL_MEMORY(&map2, curr_map, sizeof(struct mapinfo));
}

void helper_test_argenvp(void **stack, char **expected)
{
    int i;
    char **_stack = (char **)(*stack);

    for (i = 0; expected[i]; ++i, ++_stack) {
        TEST_ASSERT(strncmp(*_stack, expected[i], strlen(expected[i])) == 0);
    }

    TEST_ASSERT(*_stack == NULL);
    *stack = (void *)++_stack;
}

void helper_test_auxv(void **stack, char const *auxv_fname)
{
    uint8_t *bytes;
    size_t auxvs_sz = mmap_test_file(auxv_fname, &bytes);
    auxv_t *expected = (auxv_t *)bytes;
    auxv_t *_stack = (auxv_t *)(*stack);
    uint32_t i, j;
    size_t expected_auxv_len = auxvs_sz / sizeof(auxv_t) - 1;
    bool found_auxv;

    for (i = 0; _stack->a_type != AT_NULL && i < expected_auxv_len; ++i, ++_stack) {
        found_auxv = false;

        for (j = 0; expected[j].a_type != AT_NULL; ++j) {
            if (expected[j].a_type != _stack->a_type) {
                continue;
            }

            found_auxv = true;
            TEST_ASSERT_EQUAL(expected[j].a_un.a_val, _stack->a_un.a_val);
        }

        if (!found_auxv) {
            TEST_FAIL_MESSAGE("expected auxv not in actual");
        }
    }

    TEST_ASSERT_EQUAL(expected_auxv_len, i);
    TEST_ASSERT_EQUAL(AT_NULL, _stack->a_type);
    *stack = (void *)++_stack;
    munmap_test_file(bytes, auxvs_sz);
}

void test_dup_stack(void)
{
    uint8_t *elf;
    size_t elf_sz = mmap_test_file("elf1.bin", &elf);
    uint8_t *stack;
    char const *auxv_fpath_og = auxv_fpath;

    struct loadinfo loadinfo = {
        .interp_base_addr = (uint8_t *)0x00112233,
        .prog_base_addr = (uint8_t *)0x44556677,
        .interp_entry = 1234L,
        .prog_entry = 5678L,
        .is_stack_exec = false,
    };

    char *argv[] = {"arg1", "arg2", NULL};
    char *envp[] = {"k1=v1", "k2=v2", NULL};
    struct main_args margs = {
        .argv = argv,
        .envp = envp,
    };

    auxv_fpath = "auxv1.bin";
    stack = (uint8_t *)dup_stack((ElfW(Ehdr) *)elf, &loadinfo, &margs);
    munmap_test_file(elf, elf_sz);

    TEST_ASSERT(*(int *)stack == (sizeof(argv) / sizeof(*argv)) - 1);
    stack += sizeof(size_t);
    helper_test_argenvp((void **)&stack, argv);
    helper_test_argenvp((void **)&stack, envp);
    helper_test_auxv((void **)&stack, auxv_fpath);
    auxv_fpath = auxv_fpath_og;
}

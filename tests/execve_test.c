#include <sys/mman.h>
#include <stdbool.h>
#include <stdint.h>

#include <unity.h>
#include <cvector.h>

#include "tests/test_utils.h"
#include "execve_internal.h"

void test_append_to_maptable(void);
void test_dup_stack(void);
void test_copy_to_stack(void);

void helper_test_dup_stack(
    char const *elf_fpath, char const *auxv_fpath_input, char const *auxv_fpath_expected,
    struct main_args *margs, struct loadinfo *li
);
void helper_test_argenvp(void **stack, char const *const *expected);
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

void helper_test_argenvp(void **stack, char const *const *expected)
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

void helper_test_dup_stack(
    char const *elf_fpath, char const *auxv_fpath_input, char const *auxv_fpath_expected,
    struct main_args *margs, struct loadinfo *li
) {
    uint8_t *elf;
    size_t elf_sz = mmap_test_file(elf_fpath, &elf);
    uint8_t *stack;
    char const *auxv_fpath_og = _auxv_fpath;
    int argv_len;

    for (argv_len = 0; margs->argv[argv_len]; ++argv_len)
        ;

    _auxv_fpath = auxv_fpath_input;
    stack = (uint8_t *)dup_stack((ElfW(Ehdr) *)elf, li, margs);
    munmap_test_file(elf, elf_sz);

    TEST_ASSERT(*(int *)stack == argv_len);
    stack += sizeof(size_t);
    helper_test_argenvp((void **)&stack, margs->argv);
    helper_test_argenvp((void **)&stack, margs->envp);
    helper_test_auxv((void **)&stack, auxv_fpath_expected);
    _auxv_fpath = auxv_fpath_og;
}

void test_dup_stack(void)
{
    struct loadinfo li = {
        .interp_base_addr = (uint8_t *)0x00112233,
        .prog_base_addr = (uint8_t *)0x44556677,
        .interp_entry = 1234L,
        .prog_entry = 5678L,
        .is_stack_exec = false,
    };

    char const *const argv[] = {"arg1", "arg2", NULL};
    char const *const envp[] = {"k1=v1", "k2=v2", NULL};
    struct main_args margs = {
        .argv = argv,
        .envp = envp,
    };

    helper_test_dup_stack("elf1.bin", "auxv1.bin", "auxv1.bin", &margs, &li);
}

void test_dup_stack_missing_required_entries(void)
{
    struct loadinfo li = {
        .interp_base_addr = (uint8_t *)0x00112233,
        .prog_base_addr = (uint8_t *)0x44556677,
        .interp_entry = 1234L,
        .prog_entry = 5678L,
        .is_stack_exec = false,
    };

    char const *const argv[] = {"arg1", "arg2", NULL};
    char const *const envp[] = {"k1=v1", "k2=v2", NULL};
    struct main_args margs = {
        .argv = argv,
        .envp = envp,
    };

    helper_test_dup_stack("elf1.bin", "auxv2.bin", "auxv1.bin", &margs, &li);
}

void test_copy_to_stack(void)
{
    stack_t stack;
    struct loadinfo li;
    memset(&li, 0, sizeof(li));
    li.is_stack_exec = false;

    TEST_ASSERT(!make_stack(&stack, 32768, &li));

    char const s1[] = "Hello, world!";
    char const s2[] = "AAAAAAAAAAAAAAAAAAAA";
    char const s3[] = "";

    char const *r1, *r2, *r3, *r4;
    r1 = copy_to_stack(&stack, s1, -1);
    r2 = copy_to_stack(&stack, s2, -1);
    r3 = copy_to_stack(&stack, s3, -1);

    TEST_ASSERT_EQUAL_STRING(s1, r1);
    TEST_ASSERT_EQUAL_STRING(s2, r2);
    TEST_ASSERT_EQUAL_STRING(s3, r3);

    r4 = copy_to_stack(&stack, "BBBBAA", 4);
    TEST_ASSERT_EQUAL_STRING("BBBB", r4);
}

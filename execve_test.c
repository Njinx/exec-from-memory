#include <unity.h>
#include <cvector.h>
#include <sys/mman.h>

#include "execve_internal.h"

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
    curr_map = cvector_begin(maptable); // curr_map may not be same pointer after append
    ++curr_map;
    TEST_ASSERT_EQUAL(2, cvector_size(maptable));
    TEST_ASSERT_EQUAL_MEMORY(&map2, curr_map, sizeof(struct mapinfo));
}

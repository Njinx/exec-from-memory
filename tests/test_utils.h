#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <unistd.h>
#include <stdint.h>

size_t mmap_test_file(char const *fname, uint8_t **data);
void munmap_test_file(uint8_t *data, size_t sz);

#endif /* _TEST_UTILS_H */
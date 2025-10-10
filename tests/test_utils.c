#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <unity.h>

size_t mmap_test_file(char const *fname, uint8_t **data)
{
    int fd;
    struct stat sinfo;

    fd = open(fname, O_RDONLY);
    if (fd < 0) {
        close(fd);
        fprintf(stderr, "open %s: %s\n", fname, strerror(errno));
        exit(1);
    }

    if (stat(fname, &sinfo) < 0) {
        close(fd);
        fprintf(stderr, "stat %s: %s\n", fname, strerror(errno));
        exit(1);
    }

    *data = mmap(NULL, sinfo.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (*data == MAP_FAILED) {
        *data = NULL;
        close(fd);
        fprintf(stderr, "mmap %s: %s\n", fname, strerror(errno));
    }

    close(fd);
    return sinfo.st_size;
}

void munmap_test_file(uint8_t *data, size_t sz)
{
    munmap(data, sz);
}

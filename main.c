#define _GNU_SOURCE

#include <aes.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "config.h"
#include "execve.h"
#include "payload.h"

void aes_decrypt(unsigned char** plaintext, size_t plaintext_len);
int main(int argc, char* argv[], char* envp[]);

void aes_decrypt(unsigned char** plaintext, size_t plaintext_len)
{
    int i = 0;
    struct AES_ctx ctx;
    unsigned char buf[AES_BLOCKLEN];
    const uint8_t remainder = plaintext_len % AES_BLOCKLEN;

    if (aes_key_len != 16 && aes_key_len != 24 && aes_key_len != 32) {
        fprintf(stderr, "Invalid key size: %ld\n", aes_key_len);
        exit(1);
    }

    if (payload_data_len % AES_BLOCKLEN != 0) {
        fprintf(stderr, "Ciphertext is not a multiple of the AES blocksize\n");
        exit(1);
    }

    AES_init_ctx(&ctx, aes_key);
    memcpy(*plaintext, payload_data, plaintext_len);
    while (i < plaintext_len - remainder) {
        AES_ECB_decrypt(&ctx, *plaintext + i);
        i += AES_BLOCKLEN;
    }

    if (remainder > 0) {
        memcpy(buf, *plaintext + i, remainder);
        AES_ECB_decrypt(&ctx, buf);
        memcpy(*plaintext + i, buf, remainder);
    }
}

int main(int argc, char* argv[], char* envp[])
{
    // int dst_fd;
    unsigned char* plaintext;
    // int err;

    // if ((dst_fd = memfd_create("memfd", MFD_CLOEXEC)) < 0) {
    //     perror("memfd_create()");
    //     exit(errno);
    // }

    // if (ftruncate(dst_fd, plaintext_len) < 0) {
    //     perror("ftruncate()");
    //     exit(errno);
    // }

    // plaintext = mmap(NULL, plaintext_len,
    //     PROT_READ | PROT_WRITE | PROT_EXEC,
    //     MAP_SHARED,
    //     dst_fd, 0);
    // if (plaintext == MAP_FAILED) {
    //     perror("mmap()");
    //     exit(errno);
    // }

    // No need for munlock() as our fexecve will release it automatically
    // if ((err = mlock(plaintext, plaintext_len)) < 0) {
    //     if (MLOCK_OR_DIE) {
    //         perror("mlock()");
    //         exit(errno);
    //     }
    //     fprintf(stderr, "WARN: mlock(): %s\n", strerror(errno));
    // }

    plaintext = malloc(plaintext_len);
    aes_decrypt(&plaintext, plaintext_len);

    char* errstr = NULL;
    if (ulexecve((char*)plaintext, plaintext_len, argv, envp, &errstr) < 0) {
        if (*errstr) {
            fprintf(stderr, "ulexecve(): %s\n", errstr);
        } else {
            fprintf(stderr, "ulexecve() failed\n");
        }
        exit(EXIT_FAILURE);
    }

    // char* map_buf[8192] = { 0 };
    // FILE* fp = fopen("/proc/self/maps", "r");
    // if (fp == NULL) {
    //     perror("fread()");
    //     exit(errno);
    // }

    // size_t map_sz = fread(map_buf, sizeof(char), sizeof(map_buf), fp);
    // char* line = NULL;
    // size_t len = 0;
    // ssize_t n;
    // while ((n = getline(&line, &len, fp)) != -1) {
    //     if
    // }

    // char line_chrs[16];
    // char ch;
    // for (int i = 0; i < plaintext_len; i++) {
    //     printf("%02x ", payload_plaintext[i]);
    //     if (i != 0 && i % 16 == 15) {
    //         printf("   ");
    //         for (int j = 0; j < sizeof(line_chrs); j++) {
    //             if (line_chrs[j] >= 0x20) {
    //                 ch = line_chrs[j];
    //             } else {
    //                 ch = '.';
    //             }
    //             printf("%c", ch);
    //         }
    //         printf("\n");
    //     }
    //     line_chrs[i % 16] = payload_plaintext[i];
    // }

    // if (munmap(plaintext, plaintext_len) < 0) {
    //     perror("munmap()");
    //     exit(errno);
    // }

    // if ((err = fexecve(dst_fd, argv, envp)) < 0) {
    //     perror("fexecve()");
    //     exit(errno);
    // }

    return 0;
}
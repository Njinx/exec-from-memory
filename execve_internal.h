#ifndef __EXECVE_INTERNAL_H
#define __EXECVE_INTERNAL_H

#include <elf.h>
#include <unistd.h>
#include <stdbool.h>

#if defined(__x86_64__)
#define WORD_SIZE 64
#elif defined(__i386__)
#define WORD_SIZE 32
#else
#error "Unsupported architecture"
#endif

#define ElfW(type) _ElfW1(WORD_SIZE, type)
#define _ElfW1(word_size, type) _ElfW2(word_size, _##type)
#define _ElfW2(word_size, type) Elf##word_size##type

#if defined(UNITY_TEST)
#define testable_h(mod) extern
#define testable_c(mod)
#else
#define testable_h(mod) mod
#define testable_c(mod) mod
#endif

/* 'n' must be a power of 2 */
#define ALIGN_STACK(x, n) ((x) + (n) - (x) % (n))

#define PAGE_FLOOR(x) ((size_t)(x) - (size_t)(x) % page_size())
#define PAGE_CEIL(x) ((size_t)(x) + page_size() - (size_t)(x) % page_size() - 1)

#define EHDR(base) ((ElfW(Ehdr) const *)(base))
#define PHDR(base, i) ((ElfW(Phdr) const *)((uint8_t const *)(base) + EHDR(base)->e_phoff + sizeof(ElfW(Phdr)) * (i)))

/* The size in bytes that argc takes up on the stack. This is different than the size of
 * argc's type. On x86 ILP32 and x86_64 LP64 it's the word size and I bet this holds true on
 * other platforms.
 */
#define ARGC_STORE_SZ sizeof(size_t)
#define STACK_ALIGN 16

#define stack_curr(stack) ((stack).base - (stack).pos)

struct main_args {
    char *const *argv;
    char *const *envp;
};

typedef struct {
    size_t a_type;
    union {
        size_t a_val;
        void *a_ptr;
        void (*a_fcn)();
    } a_un;
} auxv_t;

typedef struct {
    uint8_t *base;
    size_t pos;
} stack_t;

typedef char const **errstr_t;

struct auxinfo {
    uint8_t *phdr;
    long phent;
    long phnum;
    uint8_t *entry;
    uint8_t *base;
};

/* Contains pointers to all string table objects */
struct strtable {
    struct {
        char **v;
        int c;
        size_t sz;
    } arg;
    struct {
        char **p;
        int c;
        size_t sz;
    } env;
    auxv_t *auxv;
    size_t auxv_sz;
};

struct loadinfo {
    uint8_t *interp_base_addr;
    uint8_t *prog_base_addr;
    size_t interp_entry;
    size_t prog_entry;
    bool is_stack_exec;
};

struct mapinfo {
    void *ptr;
    size_t len;
    int prot;
};

testable_h(static) void append_to_maptable(struct mapinfo map);

#ifdef DEBUGG
#define dbgprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbgprintf(...)
#endif

#endif /* __EXECVE_INTERNAL_H */
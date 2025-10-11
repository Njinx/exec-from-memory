#ifndef __EXECVE_INTERNAL_H
#define __EXECVE_INTERNAL_H

#include <elf.h>
#include <unistd.h>
#include <stdbool.h>

#include "config.h"

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

struct main_args {
    char const *const *argv;
    char const *const *envp;
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
    uint8_t *_base;
    size_t _pos;
    size_t _cap;
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
testable_h(static) void *dup_stack(ElfW(Ehdr) const *ehdr, struct loadinfo *loadinfo, struct main_args *margs);
testable_h(static) int load_elf(uint8_t const *bytes, size_t len, struct loadinfo *loadinfo, bool is_interp, errstr_t errstr);
testable_h(static) void dup_auxv(stack_t *stack, struct auxinfo *auxinfo, struct strtable *st);
testable_h(static) int make_stack(stack_t *stack, size_t sz, struct loadinfo *li);
testable_h(static) void *copy_to_stack(stack_t *stack, void const *src, ssize_t sz);

testable_h(static) char const *_auxv_fpath;

#ifdef DEBUGG
#define dbgprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbgprintf(...)
#endif

#define sizeof_arr(arr) (sizeof(arr) / sizeof(*arr))

#endif /* __EXECVE_INTERNAL_H */
#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "execve.h"

void parse_phdrs(const unsigned char* bytes, Elf64_Ehdr* ehdr);
void* dup_stack(void* load_addr, char* elf_addr);
long page_size();
void jmp_to_payload(void* entry, void* sp);

static long _page_sz = -1;
static int argc = -1;
static char** argv = NULL;

#define PAGE_FLOOR(x) ((size_t)(x) - (size_t)(x) % page_size())
#define PAGE_CEIL(x) ((size_t)(x) + page_size() - (size_t)(x) % page_size() - 1)

struct mem_region {
    unsigned char* addr;
    size_t size;
};

// The elf.h definition of this struct is wrong for some reason, we so bring our own
typedef struct {
    int a_type;
    union {
        long a_val;
        void* a_ptr;
        void (*a_fcn)();
    } a_un;
} auxv_t;

void execve_init(int _argc, char** _argv)
{
    argc = _argc;
    argv = _argv;
}

long page_size()
{
    if (_page_sz == -1) {
        _page_sz = sysconf(_SC_PAGESIZE);
        if (_page_sz == -1) {
            printf("sysconf(_SC_PAGESIZE) reports -1");
            exit(1);
        }
    }
    return _page_sz;
}

void parse_elf(const unsigned char* bytes)
{
    size_t curr_off = 0;

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)bytes;
    curr_off += sizeof(Elf64_Ehdr*);

    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        printf("Not an executable file\n");
        exit(1);
    }

    // TODO: Do more checks

    parse_phdrs(bytes, ehdr);

    // Elf64_Shdr *shdr = (Elf64_Shdr *)(bytes + sizeof(char) * ehdr->e_shoff);

    // printf("%d == %d\n", sizeof(Elf64_Phdr), ehdr->e_phentsize);
}

void parse_phdrs(const unsigned char* bytes, Elf64_Ehdr* ehdr)
{
    Elf64_Phdr* phdr;
    size_t total_sz = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        phdr = (Elf64_Phdr*)(bytes
            + sizeof(char) * ehdr->e_phoff
            + ehdr->e_phentsize * i);

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        if (phdr->p_vaddr + phdr->p_memsz > total_sz) {
            total_sz = (size_t)(phdr->p_vaddr + phdr->p_memsz);
        }
    }

    void* base_ptr = mmap(NULL, total_sz,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1, 0);
    if (base_ptr
        == MAP_FAILED) {
        perror("mmap()");
        exit(errno);
    }

    // if (mprotect(base_ptr, PAGE_CEIL(total_sz), PROT_NONE) < 0) {
    //     perror("mprotect()");
    //     exit(errno);
    // }

    for (int i = 0; i < ehdr->e_phnum; i++) {
        phdr = (Elf64_Phdr*)(bytes
            + sizeof(char) * ehdr->e_phoff
            + ehdr->e_phentsize * i);

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
        int prot = 0;
        prot |= (phdr->p_flags & PF_R) ? PROT_READ : 0;
        prot |= (phdr->p_flags & PF_W) ? PROT_WRITE : 0;
        prot |= (phdr->p_flags & PF_X) ? PROT_EXEC : 0;
        void* addr = base_ptr + phdr->p_vaddr;
        void* aligned_addr = (void*)PAGE_FLOOR(addr);
        // long off = phdr->p_offset - (addr - aligned_addr);

        if (phdr->p_filesz > phdr->p_memsz) {
            printf("phdr %d: p_filesz > p_memsz\n", i);
            exit(1);
        }

        if (aligned_addr < base_ptr || aligned_addr + phdr->p_memsz > base_ptr + total_sz) {
            printf("phdr %d: out of bounds\n", i);
            exit(1);
        }
        if (phdr->p_memsz == 0) {
            printf("phdr %d: p_memsz == 0\n", i);
            exit(1);
        }

        void* seg = mmap(aligned_addr, phdr->p_memsz, prot | PROT_WRITE, flags, -1, 0);
        if (seg == MAP_FAILED) {
            printf("pid: %u\n", getpid());
            getc(stdin);
            perror("mmap()");
            exit(errno);
        }

        // if (phdr->p_filesz - off - 1 > phdr->p_memsz) {
        //     printf("phdr %d: copy out of bounds\n", i);
        //     exit(1);
        // }

        // printf("(%p %p) <= (%ld %ld)\n", seg + off, phdr->p_memsz, phdr->p_offset, phdr->p_filesz);
        memset(seg, 0, PAGE_CEIL(phdr->p_memsz));
        memcpy(seg + (addr - aligned_addr), bytes + phdr->p_offset, phdr->p_filesz);
    }

    void* sp = dup_stack(base_ptr, bytes);

    printf("JUMPING base: %p, sp: %p\n", ehdr->e_entry + base_ptr, sp);
    jmp_to_payload(ehdr->e_entry + base_ptr, sp);
}

typedef struct {
    uint8_t* base;
    size_t pos;
} stack_t;

#define stack_curr(stack) ((stack).base - (stack).pos)

// Contains pointers to all string table objects
struct strtable {
    struct {
        char** v;
        int c;
        size_t sz;
    } arg;
    struct {
        char** p;
        int c;
        size_t sz;
    } env;
    struct {
        char* at_random;
        char* at_execfn;
    } auxv;
};

void copy_to_strtable(stack_t* stack, char** st_var, char* src, ssize_t len)
{
    size_t align_diff;
    uint8_t* aligned;

    if (len == -1) {
        len = strlen(src) + 1;
    }

    stack->pos += len;
    align_diff = (size_t)stack_curr(*stack) % sizeof(size_t);
    aligned = stack_curr(*stack) - align_diff;
    memcpy(aligned, src, len);
    stack->pos += align_diff;
    *st_var = (char*)aligned;
}

// TODO: Should probably align these pointers
void make_strtable(stack_t* stack, struct strtable* st)
{
    st->arg.c = argc;
    st->arg.sz = sizeof(*st->arg.v) * (st->arg.c + 1);
    st->arg.v = malloc(st->arg.sz);
    *stack_curr(*stack) = 0;
    stack->pos++;
    for (int i = st->arg.c - 1; i >= 0; --i) {
        copy_to_strtable(stack, st->arg.v + i, argv[i], -1);
    }

    char** env;
    for (st->env.c = 0, env = environ; *env != NULL; ++env, ++st->env.c)
        ;

    st->env.sz = sizeof(*st->env.p) * (st->env.c + 1);
    st->env.p = malloc(st->env.sz);
    *stack_curr(*stack) = 0;
    stack->pos++;
    env = environ;
    for (int i = 0; *env != NULL; ++env, ++i) {
        copy_to_strtable(stack, st->env.p + i, *env, -1);
    }

    copy_to_strtable(stack, &st->auxv.at_random, (char*)getauxval(AT_RANDOM), 16);
    copy_to_strtable(stack, &st->auxv.at_random, (char*)getauxval(AT_EXECFN), -1);
}

void free_strtable(struct strtable* st)
{
    free(st->arg.v);
    free(st->env.p);
    st->arg.v = st->env.p = NULL;
}

void* dup_stack(void* load_addr, char* elf_addr)
{
    stack_t stack; // This points to the top of the stack
    stack.pos = 0;

    size_t stack_sz = 1024 * 1024 * 10; // 10MB
    stack_sz = stack_sz + stack_sz % page_size() - 1;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN;
    if ((stack.base = mmap(NULL, stack_sz, prot, flags, -1, 0)) == MAP_FAILED) {
        perror("mmap()");
        exit(errno);
    }
    stack.base += stack_sz;

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf_addr;

    struct strtable st;
    make_strtable(&stack, &st);

    auxv_t new_auxv[] = {
        { .a_type = AT_PHDR, .a_un.a_ptr = elf_addr + ehdr->e_phoff },
        { .a_type = AT_PHENT, .a_un.a_val = ehdr->e_phentsize },
        { .a_type = AT_PHNUM, .a_un.a_val = ehdr->e_phnum },
        { .a_type = AT_ENTRY, .a_un.a_ptr = load_addr + ehdr->e_entry },
        { .a_type = AT_PAGESZ, .a_un.a_val = page_size() },
        { .a_type = AT_BASE, .a_un.a_ptr = NULL }, // TODO
        { .a_type = AT_FLAGS, .a_un.a_val = getauxval(AT_FLAGS) },
        { .a_type = AT_UID, .a_un.a_val = getauxval(AT_UID) },
        { .a_type = AT_EUID, .a_un.a_val = getauxval(AT_EUID) },
        { .a_type = AT_GID, .a_un.a_val = getauxval(AT_GID) },
        { .a_type = AT_EGID, .a_un.a_val = getauxval(AT_EGID) },
        { .a_type = AT_PLATFORM, .a_un.a_val = getauxval(AT_PLATFORM) },
        { .a_type = AT_HWCAP, .a_un.a_val = getauxval(AT_HWCAP) },
        { .a_type = AT_HWCAP2, .a_un.a_val = getauxval(AT_HWCAP2) },
        { .a_type = AT_CLKTCK, .a_un.a_val = getauxval(AT_CLKTCK) },
        { .a_type = AT_SECURE, .a_un.a_val = getauxval(AT_SECURE) },
        // { .a_type = AT_BASE_PLATFORM, .a_un.a_ptr = base_platform },
        { .a_type = AT_RANDOM, .a_un.a_ptr = st.auxv.at_random },
        { .a_type = AT_EXECFN, .a_un.a_ptr = st.auxv.at_execfn },
        { .a_type = AT_NULL },
    };

    stack.pos += sizeof(new_auxv);
    memcpy(stack_curr(stack), new_auxv, sizeof(new_auxv));

    stack.pos += st.env.sz;
    memcpy(stack_curr(stack), st.env.p, st.env.sz);

    stack.pos += st.arg.sz;
    memcpy(stack_curr(stack), st.arg.v, st.arg.sz);

    stack.pos += sizeof(uint64_t);
    *stack_curr(stack) = st.arg.c;

    free_strtable(&st);
    return stack_curr(stack);
}

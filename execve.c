#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cvector.h>

#include "execve.h"

struct main_args {
    char* const* argv;
    char* const* envp;
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

typedef struct {
    uint8_t* base;
    size_t pos;
} stack_t;

#define stack_curr(stack) ((stack).base - (stack).pos)

struct auxinfo {
    void* phdr;
    long phent;
    long phnum;
    void* entry;
};

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
    auxv_t* auxv;
    size_t auxv_sz;
};

extern void jmp_to_payload(void* addr, void* sp);

void* dup_stack(void* load_addr, char* elf_addr, struct main_args* margs);
void free_strtable(struct strtable* st);
void make_strtable(stack_t* stack, struct strtable* st, struct main_args* margs);
struct strtable* new_strtable();
void dup_auxv(stack_t* stack, struct auxinfo* auxinfo, struct strtable* st);
bool handle_auxv_ent(stack_t* stack, struct auxinfo* info, auxv_t* ent);
void* copy_to_strtable(stack_t* stack, char* src, ssize_t len);
bool map_segment(Elf64_Phdr* phdr, char* bytes, void* base_addr, size_t base_addr_sz, char** errstr);
long page_size();

#define PAGE_FLOOR(x) ((size_t)(x) - (size_t)(x) % page_size())
#define PAGE_CEIL(x) ((size_t)(x) + page_size() - (size_t)(x) % page_size() - 1)

static long _page_sz = -1;

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

int ulexecve(char* bytes, char* const argv[], char* const envp[], char** errstr)
{
    size_t curr_off = 0;

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)bytes;
    curr_off += sizeof(Elf64_Ehdr*);

    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        printf("Not an executable file\n");
        exit(1);
    }

    // TODO: Do more checks

    Elf64_Phdr* phdr;
    size_t base_addr_sz = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        phdr = (Elf64_Phdr*)(bytes
            + sizeof(char) * ehdr->e_phoff
            + ehdr->e_phentsize * i);

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        if (phdr->p_vaddr + phdr->p_memsz > base_addr_sz) {
            base_addr_sz = (size_t)(phdr->p_vaddr + phdr->p_memsz);
        }
    }

    void* base_addr = mmap(NULL, base_addr_sz,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1, 0);
    if (base_addr
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

        // TODO: How to properly do errors? Maybe Go-like chaining with an array of error strings?
        if (!map_segment(phdr, bytes, base_addr, base_addr_sz, errstr)) {
            return -1;
        }
    }

    struct main_args margs = {
        .argv = argv,
        .envp = envp,
    };

    void* sp = dup_stack(base_addr, bytes, &margs);
    jmp_to_payload(ehdr->e_entry + base_addr, sp);

    fprintf(stderr, "BUG: Return from execve? We shouldn't be here!!!\n");
    return 0;
}

bool map_segment(Elf64_Phdr* phdr, char* bytes, void* base_addr, size_t base_addr_sz, char** errstr)
{
    int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
    void* addr = base_addr + phdr->p_vaddr;
    void* aligned_addr = (void*)PAGE_FLOOR(addr);
    int prot = 0;
    prot |= (phdr->p_flags & PF_R) ? PROT_READ : 0;
    prot |= (phdr->p_flags & PF_W) ? PROT_WRITE : 0;
    prot |= (phdr->p_flags & PF_X) ? PROT_EXEC : 0;
    // long off = phdr->p_offset - (addr - aligned_addr);

    if (phdr->p_filesz > phdr->p_memsz) {
        *errstr = "p_filesz > p_memsz";
        return false;
    }

    if (aligned_addr < base_addr || aligned_addr + phdr->p_memsz > base_addr + base_addr_sz) {
        *errstr = "out of bounds";
        exit(1);
    }
    if (phdr->p_memsz == 0) {
        *errstr = "p_memsz == 0";
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

    memset(seg, 0, PAGE_CEIL(phdr->p_memsz));
    memcpy(seg + (addr - aligned_addr), bytes + phdr->p_offset, phdr->p_filesz);

    *errstr = NULL;
    return true;
}

void* copy_to_strtable(stack_t* stack, char* src, ssize_t len)
{
    if (len == -1) {
        len = strlen(src) + 1;
    }

    stack->pos += len;
    memcpy(stack_curr(*stack), src, len);
    return stack_curr(*stack);
}

/* Returns whether or not the entry should be added to the auxiliary vector
 */
bool handle_auxv_ent(stack_t* stack, struct auxinfo* info, auxv_t* ent)
{
    switch (ent->a_type) {
    case AT_EXECFD:
        return false;

    case AT_BASE: // TODO interp
        return false;

    case AT_PHDR: // TODO interp
        ent->a_un.a_ptr = info->phdr;
        return true;
    case AT_PHENT:
        ent->a_un.a_val = info->phent;
        return true;
    case AT_PHNUM:
        ent->a_un.a_val = info->phnum;
        return true;
    case AT_ENTRY:
        ent->a_un.a_ptr = info->entry;
    case AT_PAGESZ:
        ent->a_un.a_val = page_size();
        return true;
    case AT_RANDOM:
        ent->a_un.a_ptr = copy_to_strtable(stack, (char*)getauxval(AT_RANDOM), 16);
        return true;

    case AT_EXECFN:
    case AT_PLATFORM:
    case AT_BASE_PLATFORM:
        ent->a_un.a_ptr = copy_to_strtable(stack, (char*)getauxval(ent->a_type), -1);
        return true;

    case AT_FLAGS:
    case AT_UID:
    case AT_EUID:
    case AT_GID:
    case AT_EGID:
    case AT_HWCAP:
    case AT_HWCAP2:
    case AT_CLKTCK:
    case AT_NOTELF:
    case AT_SECURE:
#ifdef __i386__
    case AT_SYSINFO:
#endif
    case AT_SYSINFO_EHDR:
    case AT_DCACHEBSIZE:
    case AT_ICACHEBSIZE:
    case AT_UCACHEBSIZE:
    case AT_L1I_CACHESIZE:
    case AT_L1I_CACHEGEOMETRY:
    case AT_L1D_CACHESIZE:
    case AT_L1D_CACHEGEOMETRY:
    case AT_L2_CACHESIZE:
    case AT_L2_CACHEGEOMETRY:
    case AT_L3_CACHESIZE:
    case AT_L3_CACHEGEOMETRY:
    case AT_MINSIGSTKSZ:
#ifdef AT_RSEQ_FEATURE_SIZE
    case AT_RSEQ_FEATURE_SIZE:
#endif
#ifdef AT_RSEQ_ALIGN
    case AT_RSEQ_ALIGN:
#endif
#ifdef AT_HWCAP3
    case AT_HWCAP3:
#endif
#ifdef AT_HWCAP4
    case AT_HWCAP4:
#endif
        return true;

    case AT_IGNORE:
    case AT_NULL:
        return true;
    default:
        fprintf(stderr, "Unknown auxv a_type %x\n", ent->a_type);
        return true;
    }
}

void dup_auxv(stack_t* stack, struct auxinfo* auxinfo, struct strtable* st)
{
    cvector(auxv_t) auxv_tmp = NULL;
    FILE* fp;
    size_t n;
    auxv_t auxv_ent;

    fp = fopen("/proc/self/auxv", "rb");
    if (fp == NULL) {
        perror("fopen()");
        exit(errno);
    }

    while ((n = fread(&auxv_ent, sizeof(auxv_ent), 1, fp)) > 0) {
        if (n != 1) {
            if (feof(fp)) {
                break;
            } else {
                fprintf(stderr, "fread(): %d\n", ferror(fp));
                exit(1);
            }
        }

        if (handle_auxv_ent(stack, auxinfo, &auxv_ent)) {
            cvector_push_back(auxv_tmp, auxv_ent);
        }

        if (auxv_ent.a_type == AT_NULL) {
            break;
        }
    }

    st->auxv_sz = sizeof(auxv_t) * cvector_size(auxv_tmp);
    st->auxv = malloc(st->auxv_sz);
    memcpy(st->auxv, auxv_tmp, st->auxv_sz);
    cvector_free(auxv_tmp);
    fclose(fp);
}

struct strtable* new_strtable()
{
    struct strtable* st = malloc(sizeof(struct strtable));
    st->auxv = NULL;
    return st;
}

void make_strtable(stack_t* stack, struct strtable* st, struct main_args* margs)
{
    st->arg.c = 0;
    while (margs->argv[st->arg.c++])
        ;
    --st->arg.c;

    st->arg.sz = sizeof(*st->arg.v) * (st->arg.c + 1);
    st->arg.v = malloc(st->arg.sz);
    *stack_curr(*stack) = 0;
    stack->pos++;
    for (int i = st->arg.c - 1; i >= 0; --i) {
        st->arg.v[i] = copy_to_strtable(stack, margs->argv[i], -1);
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
        st->env.p[i] = copy_to_strtable(stack, *env, -1);
    }
}

void free_strtable(struct strtable* st)
{
    free(st->arg.v);
    free(st->env.p);
    free(st->auxv);
    st->arg.v = st->env.p = NULL;
    st->auxv = NULL;
}

void* dup_stack(void* load_addr, char* elf_addr, struct main_args* margs)
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

    struct strtable* st = new_strtable();
    make_strtable(&stack, st, margs);

    struct auxinfo auxinfo = {
        .entry = load_addr + ehdr->e_entry,
        .phdr = elf_addr + ehdr->e_phoff,
        .phent = ehdr->e_phentsize,
        .phnum = ehdr->e_phnum,
    };
    dup_auxv(&stack, &auxinfo, st);

    stack.pos += st->auxv_sz;
    memcpy(stack_curr(stack), st->auxv, st->auxv_sz);

    stack.pos += st->env.sz;
    memcpy(stack_curr(stack), st->env.p, st->env.sz);

    stack.pos += st->arg.sz;
    memcpy(stack_curr(stack), st->arg.v, st->arg.sz);

    stack.pos += sizeof(uint64_t);
    *stack_curr(stack) = st->arg.c;

    free_strtable(st);
    return stack_curr(stack);
}

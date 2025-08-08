#define _GNU_SOURCE

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/prctl.h>

#include <cvector.h>

#include "execve.h"
#include "config.h"

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

#define stack_curr(stack) ((stack).base - (stack).pos)

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

static void *dup_stack(Elf64_Ehdr const *ehdr, struct loadinfo *loadinfo, struct main_args *margs);
static void free_strtable(struct strtable* st);
static void make_strtable(stack_t *stack, struct strtable *st, struct main_args *margs);
static void dup_auxv(stack_t *stack, struct auxinfo *auxinfo, struct strtable *st);
static bool handle_auxv_ent(stack_t *stack, struct auxinfo* info, auxv_t* ent);
static void *copy_to_strtable(stack_t *stack, char *src, ssize_t len);
static int reprotect_maps();
static void append_to_maptable(struct mapinfo map);
static int map_segment(Elf64_Phdr const *phdr, uint8_t const *bytes, uint8_t const* base_addr, size_t base_addr_sz, errstr_t errstr);
static int check_prog(uint8_t const *bytes, size_t len, errstr_t errstr);
static long read_interp(uint8_t const *bytes, Elf64_Phdr const *phdr, uint8_t **data, errstr_t errstr);
static int load_elf(uint8_t const *bytes, size_t len, struct loadinfo *loadinfo, bool is_interp, errstr_t errstr);
static long page_size();
static void jmp_to_payload(uint8_t const *addr, uint8_t *sp);
static void dbg_set_map_name(uint8_t const *ptr, size_t sz, char const *name);
static int phdr_name(Elf64_Phdr const *phdr, char **name);

#ifdef DEBUGG
#define dbgprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbgprintf(...)
#endif

/* 'n' must be a power of 2 */
#define ALIGN_STACK(x, n) ((x) + (n) - (x) % (n))

#define PAGE_FLOOR(x) ((size_t)(x) - (size_t)(x) % page_size())
#define PAGE_CEIL(x) ((size_t)(x) + page_size() - (size_t)(x) % page_size() - 1)

#define EHDR(base) ((Elf64_Ehdr const *)(base))
#define PHDR(base, i) ((Elf64_Phdr const *)((uint8_t const *)(base) + EHDR(base)->e_phoff + sizeof(Elf64_Phdr) * (i)))

/* The size in bytes that argc takes up on the stack. This is different than the size of
 * argc's type. On x86 ILP32 and x86_64 LP64 it's the word size and I bet this holds true on
 * other platforms.
 */
#define ARGC_STORE_SZ sizeof(size_t)
#define STACK_ALIGN 16

static long _page_sz = -1;
cvector_vector_type(struct mapinfo) maptable = NULL;

static long page_size()
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

static long read_interp(uint8_t const *bytes, Elf64_Phdr const *phdr, uint8_t **data, errstr_t errstr)
{
    char const *path;
    struct stat info;
    FILE *fp;

    assert(phdr->p_type == PT_INTERP);

    path = INTERP_OVERRIDE;
    if (*path == '\0') {
        path = (char const *)bytes + phdr->p_offset;
        if (stat(path, &info) < 0) {
            *errstr = "Cannot stat interpreter\n";
            return -1;
        }
    }

    fp = fopen(path, "rb");
    if (!fp) {
        *errstr = "Cannot access interpreter\n";
        return -1;
    }
    *data = mmap(NULL, info.st_size, PROT_READ, MAP_PRIVATE, fileno(fp), 0);
    if (!*data) {
        *errstr = "interpreter data mmap failed\n";
    }

    fclose(fp);
    *errstr = NULL;
    return info.st_size;
}

static int check_prog(uint8_t const *bytes, size_t len, errstr_t errstr)
{
    Elf64_Ehdr const*ehdr = EHDR(bytes);

    if (len < SELFMAG) {
        *errstr = "Bad executable size\n";
        return -1;
    }
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        *errstr = "Not an ELF file\n";
        return -1;
    }
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        *errstr = "Not an executable file\n";
        return -1;
    }
    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
        *errstr = "Bad Phdr size\n";
        return -1;
    }

    return 0;
}

static int load_elf(uint8_t const *bytes, size_t len, struct loadinfo *loadinfo, bool is_interp, errstr_t errstr)
{
    Elf64_Ehdr const *ehdr = EHDR(bytes);
    Elf64_Phdr const *phdr;
    size_t base_addr_sz;
    int prot, flags;
    uint8_t *base_addr;
    bool is_dyn = false;

    if (check_prog(bytes, len, errstr) < 0) {
        return -1;
    }

    base_addr_sz = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        phdr = PHDR(bytes, i);
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        if (phdr->p_vaddr + phdr->p_memsz > base_addr_sz) {
            base_addr_sz = (size_t)(phdr->p_vaddr + phdr->p_memsz);
        }
    }

    /* No loadable segments were present (allowed by the spec) or something is seriously wrong. */
    if (base_addr_sz == 0) {
        exit(EXIT_SUCCESS);
    }

    prot = PROT_READ | PROT_WRITE;
    flags = MAP_ANONYMOUS | MAP_PRIVATE;

    /* Our base address MUST be page-aligned. Linux's mmap() always chooses a page-aligned address,
     * but I'm unsure if this is portable.
     */
    base_addr = mmap(NULL, base_addr_sz, prot, flags, -1, 0);
    if (base_addr == MAP_FAILED) {
        perror("mmap()");
        exit(errno);
    }
    memset(base_addr + base_addr_sz, 0, base_addr_sz - base_addr_sz);

    uint8_t *interp_data;
    long interp_len;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        phdr = PHDR(bytes, i);

        if (phdr->p_type == PT_INTERP) {
            if (is_dyn) {
                fprintf(stderr, "Multiple .interp sections present\n");
                exit(EXIT_FAILURE);
            }

            is_dyn = true;
            interp_len = read_interp(bytes, phdr, &interp_data, errstr);
            if (interp_len < 0) {
                return -1;
            }
            if (load_elf(interp_data, interp_len, loadinfo, true, errstr) < 0) {
                munmap(interp_data, interp_len);
                return -1;
            }
            munmap(interp_data, interp_len);
            continue;
        }

        if (phdr->p_type == PT_GNU_STACK && phdr->p_flags & PF_X) {
            loadinfo->is_stack_exec = true;
        }

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // TODO: How to properly do errors? Maybe Go-like chaining with an array of error strings?
        if (map_segment(phdr, bytes, base_addr, base_addr_sz, errstr) < 0) {
            return -1;
        }
    }

    if (is_dyn || !is_interp) {
        loadinfo->prog_base_addr = base_addr;
        loadinfo->prog_entry = ehdr->e_entry;
    } else {
        loadinfo->interp_base_addr = base_addr;
        loadinfo->interp_entry = ehdr->e_entry;
    }

    *errstr = NULL;
    return 0;
}

int ulexecve(unsigned char const* bytes, size_t len, char* const argv[], char* const envp[], char const **errstr)
{
    uint8_t const *jmp_addr;
    uint8_t *sp;

    struct loadinfo loadinfo = {
        .interp_base_addr = NULL,
        .prog_base_addr = NULL,
        .interp_entry = 0,
        .prog_entry = 0,
        .is_stack_exec = false,
    };
    struct main_args margs = {
        .argv = argv,
        .envp = envp,
    };

    if (load_elf(bytes, len, &loadinfo, false, (errstr_t)errstr) < 0) {
        return -1;
    }
    if (!loadinfo.prog_base_addr) {
        *errstr = "Failed to find entrypoint\n";
        return -1;
    }

    sp = dup_stack(EHDR(bytes), &loadinfo, &margs);
    if (!sp) {
        *errstr = "Failed to duplicate stack\n";
        return -1;
    }

    if (loadinfo.interp_base_addr) {
        jmp_addr = loadinfo.interp_base_addr + loadinfo.interp_entry;
    } else {
        jmp_addr = loadinfo.prog_base_addr + loadinfo.prog_entry;
    }
    assert(jmp_addr && sp);

    if (reprotect_maps() < 0) {
        perror("reprotect_maps()");
        return -errno;
    }

    jmp_to_payload(jmp_addr, sp);

    fprintf(stderr, "BUG: Return from execve? We shouldn't be here!!!\n");
    *errstr = NULL;
    return -1;
}

static void append_to_maptable(struct mapinfo map)
{
    cvector_push_back(maptable, map);
}

static int reprotect_maps()
{
    struct mapinfo *map;

    if (!maptable) {
        return 0;
    }

    for (map = cvector_begin(maptable); map != cvector_end(maptable); ++map) {
        if (mprotect(map->ptr, map->len, map->prot) < 0) {
            return -errno;
        }
    }
    return 0;
}

static void dbg_set_map_name(uint8_t const *ptr, size_t sz, char const *name)
{
#if defined(DEBUGG) && defined(PR_SET_VMA_ANON_NAME)
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, sz, name);
#endif
}

static int phdr_name(Elf64_Phdr const *phdr, char **name)
{
    char const *pt;
    char prot[4];
    char const *fmt = "%s:0x%06lx:%s";
    int len;

#define pt_case(type) case type: pt = #type; break;
    switch (phdr->p_type) {
    pt_case(PT_NULL)
    pt_case(PT_LOAD)
    pt_case(PT_DYNAMIC)
    pt_case(PT_INTERP)
    pt_case(PT_NOTE)
    pt_case(PT_SHLIB)
    pt_case(PT_PHDR)
    pt_case(PT_TLS)
    pt_case(PT_NUM)
    pt_case(PT_LOOS)
    pt_case(PT_GNU_EH_FRAME)
    pt_case(PT_GNU_STACK)
    pt_case(PT_GNU_RELRO)
    pt_case(PT_GNU_PROPERTY)
    pt_case(PT_LOPROC)
    pt_case(PT_HIPROC)
    default:
        pt = "PT_UNKNOWN";
        break;
    }
#undef pt_case

    prot[0] = (phdr->p_flags & PF_R) ? 'R' : '-';
    prot[1] = (phdr->p_flags & PF_W) ? 'W' : '-';
    prot[2] = (phdr->p_flags & PF_X) ? 'X' : '-';
    prot[3] = '\0';

    len = snprintf(NULL, 0, fmt, prot, phdr->p_offset, pt) + 1;
    *name = malloc(len);
    return snprintf(*name, len, fmt, prot, phdr->p_offset, pt);
}

static int map_segment(Elf64_Phdr const *phdr, uint8_t const *bytes, uint8_t const *base_addr, size_t base_addr_sz, errstr_t errstr)
{
    int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
    int prot = PROT_NONE;
    bool needs_reprotect;
    uint8_t const *addr;
    uint8_t *aligned_addr, *seg;
    size_t sz;
    char *name;

    addr = base_addr + phdr->p_vaddr;
    aligned_addr = (void *)PAGE_FLOOR(addr);
    sz = phdr->p_memsz + (addr - aligned_addr);

    prot |= (phdr->p_flags & PF_R) ? PROT_READ : 0;
    prot |= (phdr->p_flags & PF_W) ? PROT_WRITE : 0;
    prot |= (phdr->p_flags & PF_X) ? PROT_EXEC : 0;

    assert(phdr->p_filesz <= phdr->p_memsz);
    assert(aligned_addr >= base_addr && aligned_addr + sz <= base_addr + base_addr_sz);
    assert(phdr->p_memsz > 0);

    needs_reprotect = (prot & PROT_WRITE) ? false : true;
    seg = mmap(aligned_addr, sz, prot | PROT_WRITE, flags, -1, 0);
    if (seg == MAP_FAILED) {
        perror("mmap()");
        exit(errno);
    }

    phdr_name(phdr, &name);
    dbg_set_map_name(seg, sz, name);
    free(name);

    // // Copy segment into memory and zero the remainder of the last page
    // TODO: Make sure the `p_filesz` and `sz` discrepancy won't cause any issues
    memcpy(seg + (addr - aligned_addr), bytes + phdr->p_offset, phdr->p_filesz);
    // memset(seg + sz, 0, PAGE_CEIL(sz) - sz);

    if (needs_reprotect) {
        append_to_maptable((struct mapinfo) {
            .ptr = seg,
            .len = PAGE_CEIL(sz),
            .prot = prot,
        });
    }

    *errstr = NULL;
    return 0;
}

static void* copy_to_strtable(stack_t* stack, char* src, ssize_t len)
{
    if (len == -1) {
        len = strlen(src) + 1;
    }

    stack->pos += len;
    memcpy(stack_curr(*stack), src, len);
    return stack_curr(*stack);
}

/* Returns whether or not the entry should be added to the auxiliary vector */
static bool handle_auxv_ent(stack_t* stack, struct auxinfo* info, auxv_t* ent)
{
    switch (ent->a_type) {
    case AT_EXECFD:
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
        return true;
    case AT_BASE:
        ent->a_un.a_ptr = info->base;
        return true;
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
        dbgprintf("Unknown auxv a_type %zu\n", ent->a_type);
        return true;
    }
}

static void dup_auxv(stack_t* stack, struct auxinfo* auxinfo, struct strtable* st)
{
    cvector(auxv_t) auxv_tmp = NULL;
    FILE* fp;
    size_t n;
    auxv_t auxv_ent;
    size_t const required_at[] = { AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM };

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

    assert(cvector_back(auxv_tmp)->a_type == AT_NULL);

    /* Add required entries that may not be present in the current process */
    size_t i;
    bool found;
    auxv_t *ent;
    auxv_t tmp_ent;
    for (i = 0; i < sizeof(required_at) / sizeof(*required_at); ++i) {
        found = false;
        for (ent = auxv_tmp; ent->a_type != AT_NULL; ++ent) {
            if (ent->a_type == required_at[i]) {
                found = true;
                break;
            }
        }

        if (!found) {
            tmp_ent.a_type = required_at[i];
            if (!handle_auxv_ent(stack, auxinfo, &tmp_ent)) {
                fprintf(stderr, "handle_auxv_ent(): required argument was skipped.\n");
            }
            cvector_push_back(auxv_tmp, auxv_ent);
        }
    }

    st->auxv_sz = cvector_size(auxv_tmp) * sizeof(auxv_t);
    st->auxv = malloc(st->auxv_sz);
    memcpy(st->auxv, auxv_tmp, st->auxv_sz);
    cvector_free(auxv_tmp);
    fclose(fp);
}

static void make_strtable(stack_t *stack, struct strtable *st, struct main_args *margs)
{
    int i;
    char **env;

    for (st->arg.c = 0; margs->argv[st->arg.c]; ++st->arg.c)
        ;

    st->arg.sz = sizeof(*st->arg.v) * (st->arg.c + 1);
    st->arg.v = malloc(st->arg.sz);
    *(size_t*)stack_curr(*stack) = 0L;
    stack->pos += sizeof(size_t);
    for (i = st->arg.c - 1; i >= 0; --i) {
        st->arg.v[i] = copy_to_strtable(stack, margs->argv[i], -1);
    }

    for (st->env.c = 0, env = environ; *env != NULL; ++env, ++st->env.c)
        ;

    st->env.sz = sizeof(*st->env.p) * (st->env.c + 1);
    st->env.p = malloc(st->env.sz);
    *(size_t*)stack_curr(*stack) = 0L;
    stack->pos += sizeof(size_t);
    env = environ;
    st->env.p[0] = NULL;
    for (i = 1; *env != NULL; ++env, ++i) {
        st->env.p[i] = copy_to_strtable(stack, *env, -1);
    }
}

static void free_strtable(struct strtable *st)
{
    if (st->arg.v) {
        free(st->arg.v);
    }
    if (st->env.p) {
        free(st->env.p);
    }
    if (st->auxv) {
        free(st->auxv);
    }
    st->arg.v = st->env.p = NULL;
    st->auxv = NULL;
}

static void* dup_stack(Elf64_Ehdr const* ehdr, struct loadinfo* loadinfo, struct main_args* margs)
{
    stack_t stack; // This points to the top of the stack
    size_t stack_sz = 1024 * 1024 * 10; // 10MB
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN;
    struct strtable* st;

    stack.pos = 0;
    stack_sz += stack_sz % page_size();

    if (loadinfo->is_stack_exec) {
        prot |= PROT_EXEC;
    }
    if ((stack.base = mmap(NULL, stack_sz + 1, prot, flags, -1, 0)) == MAP_FAILED) {
        perror("mmap()");
        exit(errno);
    }
    dbg_set_map_name(stack.base, stack_sz + 1, "stack");
    stack.base += stack_sz;

    st = calloc(1, sizeof(struct strtable));
    make_strtable(&stack, st, margs);

    struct auxinfo auxinfo = {
        .phdr = loadinfo->prog_base_addr + ehdr->e_phoff,
        .phent = ehdr->e_phentsize,
        .phnum = ehdr->e_phnum,
    };

    auxinfo.base = loadinfo->interp_base_addr ? loadinfo->interp_base_addr : NULL;
    auxinfo.entry = loadinfo->prog_base_addr + loadinfo->prog_entry;

    dup_auxv(&stack, &auxinfo, st);

    /* SysV wants the stack to be aligned to 16 bytes. Align enough here so that argc
     * takes care of the rest.
     */
    assert(STACK_ALIGN >= ARGC_STORE_SZ);
    stack.pos = ALIGN_STACK(stack.pos, STACK_ALIGN);
    if ((st->arg.sz + st->env.sz) % STACK_ALIGN == 0) {
        stack.pos += ARGC_STORE_SZ;
    }

    assert(st->auxv_sz % STACK_ALIGN == 0);
    assert(st->arg.sz % sizeof(size_t) == 0);
    assert(st->env.sz % sizeof(size_t) == 0);

    stack.pos += st->auxv_sz;
    memcpy(stack_curr(stack), st->auxv, st->auxv_sz);

    stack.pos += st->env.sz;
    memcpy(stack_curr(stack), st->env.p, st->env.sz);

    stack.pos += st->arg.sz;
    memcpy(stack_curr(stack), st->arg.v, st->arg.sz);

    assert((size_t)stack_curr(stack) % STACK_ALIGN == ARGC_STORE_SZ);
    stack.pos += ARGC_STORE_SZ;
    *(int*)stack_curr(stack) = st->arg.c;
    free_strtable(st);

    assert((size_t)stack_curr(stack) % STACK_ALIGN == 0);
    return stack_curr(stack);
}

__attribute__((naked,noreturn))
static void jmp_to_payload(uint8_t const *addr, uint8_t *sp)
{
    /* We're clearing most registers, including rbp. So stack-frame-relative addressing won't work
     * and we must jmp via an absolute or rip-relative address. Storing the address in global
     * memory will do the trick.
     */
    static volatile uint8_t const *nooff_addr;
    nooff_addr = addr;

    __asm__ volatile (
        "pop rbp\n" /* Discard return pointer (it'll mess up stack alignment) */
        "fnclex\n"
        "mov rsp, %1\n"
        /* Most of these aren't required to be cleared per the spec. This is simply a precaution. */
        "xor rbp, rbp\n"
        "xor rdx, rdx\n"
        "xor rax, rax\n"
        "xor rbx, rbx\n"
        "xor rbp, rbp\n"
        "xor rcx, rcx\n"
        "xor rdi, rdi\n"
        "xor rsi, rsi\n"
        "xor r8, r8\n"
        "xor r9, r9\n"
        "xor r10, r10\n"
        "xor r11, r11\n"
        "xor r12, r12\n"
        "xor r13, r13\n"
        "xor r14, r14\n"
        "xor r15, r15\n"
        "jmp %0\n"
        :
        : "m"(nooff_addr), "r"(sp)
    );
    __builtin_unreachable();
}

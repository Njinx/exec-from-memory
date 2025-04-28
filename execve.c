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
    void* base;
    // void* execfd;
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

struct loadinfo {
    void* interp_base_addr;
    void* prog_base_addr;
    size_t interp_entry;
    size_t prog_entry;
    void* dt_fini_ptr;
    bool is_stack_exec;
};

struct mapinfo {
    void *ptr;
    size_t len;
    int prot;
};


void* dup_stack(Elf64_Ehdr* ehdr, struct loadinfo* loadinfo, struct main_args* margs);
void free_strtable(struct strtable* st);
void make_strtable(stack_t* stack, struct strtable* st, struct main_args* margs);
struct strtable* new_strtable();
void dup_auxv(stack_t* stack, struct auxinfo* auxinfo, struct strtable* st);
bool handle_auxv_ent(stack_t* stack, struct auxinfo* info, auxv_t* ent);
void* copy_to_strtable(stack_t* stack, char* src, ssize_t len);
int reprotect_maps();
void append_to_maptable(struct mapinfo map);
int map_segment(Elf64_Phdr* phdr, char const* bytes, void* base_addr, size_t base_addr_sz, char** errstr);
int read_interp(char const* bytes, Elf64_Phdr* phdr, char const** data, char** errstr);
int load_elf(char const* bytes, struct loadinfo* loadinfo, bool is_interp, char** errstr);
long page_size();
void jmp_to_payload(void* addr, void* sp);

#define ALIGN_STACK(x, n) ((x) + (n) - (x) % (n))
#define PAGE_FLOOR(x) ((size_t)(x) - (size_t)(x) % page_size())
#define PAGE_CEIL(x) ((size_t)(x) + page_size() - (size_t)(x) % page_size() - 1)

#define EHDR(base) ((Elf64_Ehdr*)(base))
#define PHDR(base, i) ((Elf64_Phdr*)((void*)(base) + EHDR(base)->e_phoff + EHDR(base)->e_phentsize * (i)))

/* The size in bytes that argc takes up on the stack. This is different than the size of
 * argc's type. On x86 ILP32 and x86_64 LP64 it's the word size and I bet this holds true on
 * other platforms.
 */
#define ARGC_STORE_SZ sizeof(size_t)
#define STACK_ALIGN 16

static long _page_sz = -1;
cvector_vector_type(struct mapinfo) maptable = NULL;

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

// TODO: make data const
int read_interp(char const* bytes, Elf64_Phdr* phdr, char const** data, char** errstr)
{
    assert(phdr->p_type == PT_INTERP);

    char const* path = bytes + phdr->p_offset;
    struct stat info;
    if (stat(path, &info) < 0) {
        *errstr = "Cannot stat interpreter\n";
        return -1;
    }

    FILE* fp = fopen(path, "rb");
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
    return 0;
}

// struct dyninfo {
//     Elf64_Addr dt_fini;
// };

// void parse_dyn_table(void* base, size_t sz, struct dyninfo* dinfo)
// {
//     for (Elf64_Dyn* dyn = base; dyn < base + sz; dyn += sizeof(Elf64_Dyn)) {
//         printf("d_tag: %lu\n", dyn->d_tag);
//         switch (dyn->d_tag) {
//         case DT_FINI:
//             dinfo->dt_fini = dyn->d_un.d_ptr;
//             break;
//         }
//     }
// }

int load_elf(char const* bytes, struct loadinfo* loadinfo, bool is_interp, char** errstr)
{
    Elf64_Ehdr* ehdr = EHDR(bytes);

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        *errstr = "Not an ELF file\n";
        return -1;
    }

    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        *errstr = "Not an executable file\n";
        return -1;
    }

    // TODO: Do more checks

    Elf64_Phdr* phdr;
    size_t base_addr_sz = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        phdr = PHDR(bytes, i);
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        if (phdr->p_vaddr + phdr->p_memsz > base_addr_sz) {
            base_addr_sz = (size_t)(phdr->p_vaddr + phdr->p_memsz);
        }
    }

    /* No loadable segments were present (allowed by the spec) or something is seriously wrong.
     */
    if (base_addr_sz == 0) {
        exit(EXIT_SUCCESS);
    }
    // base_addr_sz = PAGE_CEIL(base_addr_sz);

    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    void* base_addr = mmap(NULL, base_addr_sz, prot, flags, -1, 0);
    if (base_addr == MAP_FAILED) {
        perror("mmap()");
        exit(errno);
    }

    // TODO: Parse DT_DYNAMIC if exists. We need DT_FINI and probably DT_INIT.

    bool is_dyn = false;
    // struct dyninfo dinfo;
    // bool has_dyninfo = false;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        phdr = PHDR(bytes, i);

        if (phdr->p_type == PT_INTERP) {
            if (is_dyn) {
                fprintf(stderr, "Multiple .interp sections present\n");
                exit(EXIT_FAILURE);
            }

            is_dyn = true;
            char const *interp_data;
            if (read_interp(bytes, phdr, &interp_data, errstr) < 0) {
                return -1;
            }
            if (load_elf(interp_data, loadinfo, true, errstr) < 0) {
                return -1;
            }
            continue;
        }

        if (phdr->p_type == PT_GNU_STACK && phdr->p_flags & PF_X) {
            loadinfo->is_stack_exec = true;
        }

        // if (phdr->p_type == PT_DYNAMIC) {
        //     parse_dyn_table((void*)bytes + phdr->p_offset, phdr->p_filesz, &dinfo);
        //     has_dyninfo = true;
        // }

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // TODO: How to properly do errors? Maybe Go-like chaining with an array of error strings?
        if (map_segment(phdr, bytes, base_addr, base_addr_sz, errstr) < 0) {
            return -1;
        }
    }

    if (is_dyn || !is_interp) {
    // if (!is_interp) {
        loadinfo->prog_base_addr = base_addr;
        loadinfo->prog_entry = ehdr->e_entry;
    } else {
        loadinfo->interp_base_addr = base_addr;
        loadinfo->interp_entry = ehdr->e_entry;
        // assert(has_dyninfo);
        // loadinfo->dt_fini_ptr = (void*)dinfo.dt_fini;
    }
    // fprintf(stderr, "prog_base_addr: %p\n", loadinfo->prog_base_addr);
    // fprintf(stderr, "interp_base_addr: %p\n", loadinfo->interp_base_addr);

    *errstr = NULL;
    return 0;
}

int ulexecve(char const* bytes, char* const argv[], char* const envp[], char** errstr)
{
    struct loadinfo loadinfo = {
        .interp_base_addr = NULL,
        .prog_base_addr = NULL,
        .interp_entry = 0,
        .prog_entry = 0,
        .dt_fini_ptr = NULL,
        .is_stack_exec = false,
    };
    if (load_elf(bytes, &loadinfo, false, errstr) < 0) {
        return -1;
    }
    if (!loadinfo.prog_base_addr) {
        *errstr = "Failed to find entrypoint\n";
        return -1;
    }

    struct main_args margs = {
        .argv = argv,
        .envp = envp,
    };
    // printf("interp_base_addr: %c\n", );
    void* sp = dup_stack(EHDR(bytes), &loadinfo, &margs);
    if (!sp) {
        *errstr = "Failed to duplicate stack\n";
        return -1;
    }

    void* jmp_addr;
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

void append_to_maptable(struct mapinfo map)
{
    cvector_push_back(maptable, map);
}

int reprotect_maps()
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

void set_map_name(void *ptr, size_t sz, char *name)
{
#ifdef PR_SET_VMA_ANON_NAME
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, sz, name);
#endif
}

int phdr_name(Elf64_Phdr *phdr, char **name)
{
    char *pt;

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

    char prot[4];
    prot[0] = (phdr->p_flags & PF_R) ? 'R' : '-';
    prot[1] = (phdr->p_flags & PF_W) ? 'W' : '-';
    prot[2] = (phdr->p_flags & PF_X) ? 'X' : '-';
    prot[3] = '\0';

    // Note: This trick requires C99 and SUSv3 or greater
    char const *fmt = "%s:0x%06lx:%s";
    int len = snprintf(NULL, 0, fmt, prot, phdr->p_offset, pt) + 1;
    *name = malloc(len);
    return snprintf(*name, len, fmt, prot, phdr->p_offset, pt);

#undef pt_case
}

int map_segment(Elf64_Phdr* phdr, char const* bytes, void* base_addr, size_t base_addr_sz, char** errstr)
{
    int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
    void* addr = base_addr + phdr->p_vaddr;
    void* aligned_addr = (void*)PAGE_FLOOR(addr);
    size_t sz = phdr->p_filesz + (addr - aligned_addr);
    int prot = 0;
    prot |= (phdr->p_flags & PF_R) ? PROT_READ : 0;
    prot |= (phdr->p_flags & PF_W) ? PROT_WRITE : 0;
    prot |= (phdr->p_flags & PF_X) ? PROT_EXEC : 0;
    // long off = phdr->p_offset - (addr - aligned_addr);

    /*
     * Saw this comment:
     * The ELF format is different from PE, the segments are not extended to fill the slack space
     * between. So all data and code is joined together with just the section headers between. You
     * can't change that, it is the ELF format. When the loader allocates the pages in memory you
     * will find "gaps" before and after each section where the code and data has been skipped to
     * match the file arrangement.
     *
     * Should we be using p_filesz instead of p_memsz for size calculation? Maybe that's why we're
     * segfaulting.
     */

    assert(phdr->p_filesz <= phdr->p_memsz);
    assert(aligned_addr >= base_addr && aligned_addr + phdr->p_memsz <= base_addr + base_addr_sz);
    assert(phdr->p_memsz > 0);

    // We need write permission to write to these pages, we'll remove it later with reprotect_maps()
    void* seg = mmap(aligned_addr, PAGE_CEIL(sz), prot | PROT_WRITE, flags, -1, 0);
    if (seg == MAP_FAILED) {
        perror("mmap()");
        exit(errno);
    }


    char *name;
    phdr_name(phdr, &name);
    set_map_name(seg, PAGE_CEIL(sz), name);
    free(name);

    // if (phdr->p_filesz - off - 1 > phdr->p_memsz) {
    //     printf("phdr %d: copy out of bounds\n", i);
    //     exit(1);
    // }

    // // Copy segment into memory and zero the remainder of the last page
    memcpy(seg, bytes + phdr->p_offset, sz);
    // memset(seg + sz, 0, PAGE_CEIL(sz) - sz);

    // memset(seg, 0, PAGE_CEIL(sz));
    // memcpy(seg + (addr - aligned_addr), bytes + phdr->p_offset, sz);
    struct mapinfo minfo = {
        .ptr = seg,
        .len = PAGE_CEIL(sz),
        .prot = prot,
    };
    append_to_maptable(minfo);
    // if (mprotect(seg, PAGE_CEIL(sz), prot) < 0) {
    //     perror("mprotect()");
    //     exit(errno);
    // }

    *errstr = NULL;
    return 0;
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

    case AT_PHDR: // TODO interp
        ent->a_un.a_ptr = info->phdr;
        printf("!!phdr: %p\n", info->phdr);
        return true;
    case AT_PHENT:
        ent->a_un.a_val = info->phent;
        return true;
    case AT_PHNUM:
        ent->a_un.a_val = info->phnum;
        return true;
    case AT_ENTRY:
        ent->a_un.a_ptr = info->entry;
        printf("!!entr: %p\n", info->entry);
        return true;
    case AT_BASE:
        ent->a_un.a_ptr = info->base;
        printf("!!base: %p\n", info->base);
        return true;
    // case AT_EXECFD:
    //     ent->a_un.a_ptr = info->execfd;
    //     return true;
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

    assert(cvector_back(auxv_tmp)->a_type == AT_NULL);

    // Add required entries that may not be present in the current process
    long const required[] = { AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM };
    for (int i = 0; i < sizeof(required) / sizeof(*required); ++i) {
        bool found = false;
        for (auxv_t* ent = auxv_tmp; ent->a_type != AT_NULL; ++ent) {
            if (ent->a_type == required[i]) {
                found = true;
                break;
            }
        }

        if (!found) {
            auxv_t ent = { .a_type = required[i] };
            if (!handle_auxv_ent(stack, auxinfo, &ent)) {
                fprintf(stderr, "handle_auxv_ent(): required argument was skipped.\n");
            }
            cvector_push_back(auxv_tmp, auxv_ent);
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
    *(size_t*)stack_curr(*stack) = 0L;
    stack->pos += sizeof(size_t);
    for (int i = st->arg.c - 1; i >= 0; --i) {
        st->arg.v[i] = copy_to_strtable(stack, margs->argv[i], -1);
    }

    char** env;
    for (st->env.c = 0, env = environ; *env != NULL; ++env, ++st->env.c)
        ;

    st->env.sz = sizeof(*st->env.p) * (st->env.c + 1);
    st->env.p = malloc(st->env.sz);
    *(size_t*)stack_curr(*stack) = 0L;
    stack->pos += sizeof(size_t);
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

void* dup_stack(Elf64_Ehdr* ehdr, struct loadinfo* loadinfo, struct main_args* margs)
{
    stack_t stack; // This points to the top of the stack
    stack.pos = 0;
    // stack.pos += (16 - 924 % 16) % 16;

    size_t stack_sz = 1024 * 1024 * 10; // 10MB
    stack_sz += stack_sz % page_size();
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN;
    if (loadinfo->is_stack_exec) {
        prot |= PROT_EXEC;
    }
    if ((stack.base = mmap(NULL, stack_sz + 1, prot, flags, -1, 0)) == MAP_FAILED) {
        perror("mmap()");
        exit(errno);
    }
    stack.base += stack_sz;

    struct strtable* st = new_strtable();
    make_strtable(&stack, st, margs);

    // printf("prog_base_addr = %p, e_entry = %ld, e_phoff = %ld\n", loadinfo->prog_base_addr, ehdr->e_entry, ehdr->e_phoff);
    struct auxinfo auxinfo = {
        .phdr = loadinfo->prog_base_addr + ehdr->e_phoff,
        .phent = ehdr->e_phentsize,
        .phnum = ehdr->e_phnum,
    };

    if (loadinfo->interp_base_addr) {
        auxinfo.entry = loadinfo->prog_base_addr + loadinfo->prog_entry;
        auxinfo.base = loadinfo->interp_base_addr;
    } else {
        auxinfo.entry = NULL;
        auxinfo.base = NULL;
    }

    dup_auxv(&stack, &auxinfo, st);

    /* We want stack to be aligned to 16 bytes. Align enough here so that argc
     * takes care of the rest.
     */
    assert(STACK_ALIGN >= ARGC_STORE_SZ);
    stack.pos = ALIGN_STACK(stack.pos, STACK_ALIGN);
    if ((st->arg.sz + st->env.sz) % 2 == 0) {
        stack.pos += ARGC_STORE_SZ;
    }

    // This is wrong as it only includes the strtable size + sizeof(int)
    // size_t total_sz = st->auxv_sz + st->env.sz + st->arg.sz + sizeof(st->arg.c);
    // fprintf(stderr, "total_sz: %ld\n", total_sz);

    // /* Align the stack to a 24 byte boundary as argc will correct this to the required 16 bytes.
    //  * It's important that this happens at the boundary between the string table and rest of our
    //  * initial stack, as the layout after the string table cannot be changed.
    //  */
    // stack.pos += (16 - stack.pos % 16) % 16 - sizeof(uint32_t);
    // stack.pos += (16 - total_sz % 16) % 16;

    assert(st->auxv_sz % STACK_ALIGN == 0);
    assert(st->arg.sz % sizeof(size_t) == 0);
    assert(st->env.sz % sizeof(size_t) == 0);

    // NOTE: Problem seems to be with `EVar2 = (main_map->l_info[5]->d_un).d_val` in
    // audit_list_add_dynamic_tag

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
void jmp_to_payload(void* addr, void* sp)
{
    __asm__ volatile (
        "pop rbp\n" // Discard return pointer (it'll mess up stack alignment)
        "fnclex\n"
        "mov rsp, %1\n"
        "xor rbp, rbp\n"
        "xor rdx, rdx\n"
        "jmp %0\n"
        :
        : "r"(addr), "r"(sp)
    );
    __builtin_unreachable();
}

#include <stdio.h>
#include <elf.h>

extern char **environ;

static char *auxv_str[128];

char *auxv_type_str(int type)
{
    switch (type) {
    case AT_NULL: return "AT_NULL";
	case AT_IGNORE: return "AT_IGNORE";
	case AT_EXECFD: return "AT_EXECFD";
	case AT_PHDR: return "AT_PHDR";
	case AT_PHENT: return "AT_PHENT";
	case AT_PHNUM: return "AT_PHNUM";
	case AT_PAGESZ: return "AT_PAGESZ";
	case AT_BASE: return "AT_BASE";
	case AT_FLAGS: return "AT_FLAGS";
	case AT_ENTRY: return "AT_ENTRY";
	case AT_NOTELF: return "AT_NOTELF";
	case AT_UID: return "AT_UID";
	case AT_EUID: return "AT_EUID";
	case AT_GID: return "AT_GID";
	case AT_EGID: return "AT_EGID";
	case AT_CLKTCK: return "AT_CLKTCK";
	case AT_PLATFORM: return "AT_PLATFORM";
	case AT_HWCAP: return "AT_HWCAP";
	case AT_FPUCW: return "AT_FPUCW";
	case AT_DCACHEBSIZE: return "AT_DCACHEBSIZE";
	case AT_ICACHEBSIZE: return "AT_ICACHEBSIZE";
	case AT_UCACHEBSIZE: return "AT_UCACHEBSIZE";
	case AT_IGNOREPPC: return "AT_IGNOREPPC";
	case AT_BASE_PLATFORM: return "AT_BASE_PLATFORM";
	case AT_RANDOM: return "AT_RANDOM";
	case AT_HWCAP2: return "AT_HWCAP2";
	case AT_EXECFN: return "AT_EXECFN";
	case AT_SYSINFO: return "AT_SYSINFO";
	case AT_SYSINFO_EHDR: return "AT_SYSINFO_EHDR";
	case AT_L1I_CACHESHAPE: return "AT_L1I_CACHESHAPE";
	case AT_L1D_CACHESHAPE: return "AT_L1D_CACHESHAPE";
	case AT_L2_CACHESHAPE: return "AT_L2_CACHESHAPE";
	case AT_L3_CACHESHAPE: return "AT_L3_CACHESHAPE";
	case AT_L1I_CACHESIZE: return "AT_L1I_CACHESIZE";
	case AT_L1I_CACHEGEOMETRY: return "AT_L1I_CACHEGEOMETRY";
	case AT_L1D_CACHESIZE: return "AT_L1D_CACHESIZE";
	case AT_L1D_CACHEGEOMETRY: return "AT_L1D_CACHEGEOMETRY";
	case AT_L2_CACHESIZE: return "AT_L2_CACHESIZE";
	case AT_L2_CACHEGEOMETRY: return "AT_L2_CACHEGEOMETRY";
	case AT_L3_CACHESIZE: return "AT_L3_CACHESIZE";
	case AT_L3_CACHEGEOMETRY: return "AT_L3_CACHEGEOMETRY";
	case AT_MINSIGSTKSZ: return "AT_MINSIGSTKSZ";
    default: return "UNKNOWN";
    }
}

int main(int argc, char *argv[])
{
    char **env;
    int i;
    Elf64_auxv_t *auxv;

    printf("argv\n");
    for (i = 0; i < argc; ++i) {
        printf("  %s\n", argv[i]);
    }

    printf("envp\n");
    for (env = environ; *env; ++env) {
        printf("  %s\n", *env);
    }

    printf("auxv\n");
    for (auxv = (Elf64_auxv_t *)(env + 1); auxv->a_type != AT_NULL; ++auxv) {
        char *a_type = auxv_type_str(auxv->a_type);
        printf("  {\n");
        printf("    a_type = %s (%ld)\n", a_type, auxv->a_type);
        printf("    a_val  = %ld\n", auxv->a_un.a_val);
        printf("  }\n");
    }

    return 0;
}
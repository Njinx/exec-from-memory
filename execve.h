#ifndef __EXECVE_H
#define __EXECVE_H

#if defined(__x86_64__)
// TODO
#elif defined(__i386__)
// TODO
#else

#error "Unsupported architecture"

#endif

void execve_init(int _argc, char** _argv);
void parse_elf(const unsigned char* bytes);
extern void jmp_to_payload(void* entry, void* sp);

#endif /* __EXECVE_H */
#ifndef __EXECVE_H
#define __EXECVE_H

#if defined(__x86_64__)
// TODO
#elif defined(__i386__)
// TODO
#else

#error "Unsupported architecture"

#endif

extern int ulexecve(unsigned char const* bytes, size_t len, char* const argv[], char* const envp[], char const **errstr);

#endif /* __EXECVE_H */
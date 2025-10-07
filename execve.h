#ifndef __EXECVE_H
#define __EXECVE_H

extern int ulexecve(unsigned char const* bytes, size_t len, char* const argv[], char* const envp[], char const **errstr);

#endif /* __EXECVE_H */
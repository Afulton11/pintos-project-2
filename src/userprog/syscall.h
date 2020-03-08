#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"

void syscall_init (void);

void system_exit(int error_code);
int system_wait(pid_t pid);

#endif /* userprog/syscall.h */

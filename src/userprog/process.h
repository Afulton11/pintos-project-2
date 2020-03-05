#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "user/syscall.h"
#include "threads/thread.h"

/* represents a process in the OS, AKA PCB or Task Control Block */
struct process_control_block {
  pid_t pid;  /* pid of the process */
  const char *cmd_line; /* the line used to execute this process */
};

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */

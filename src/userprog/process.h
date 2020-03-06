#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "user/syscall.h"
#include "threads/synch.h"

/* represents a process in the OS, AKA PCB or Task Control Block */
struct process_control_block {
  pid_t pid;  /* pid of the process */
  const char *cmd_line; /* the line used to execute this process */

  struct semaphore start_sema; /* semaphore used to wait until the process has been started. */
};

struct file_descriptor {
  int id;
  struct file *file;
  struct list_elem elem;
}

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */

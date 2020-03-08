#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "user/syscall.h"
#include "threads/synch.h"

/* represents a process in the OS, AKA PCB or Task Control Block */
struct process_control_block {
  pid_t pid;  /* pid of the process */
  const char *cmd_line; /* the line used to execute this process */

  bool is_waiting;    /* whether or not the process is currently waiting */
  bool has_exited;     /* whether this process has exited. */
  bool is_orphan;     /* whether this child's parent has been terminated */
  int exitcode;

  struct thread* parent;
  struct list_elem elem;

  struct semaphore start_sema; /* semaphore used to wait until the process has been started. */
  struct semaphore wait_sema; /* semaphore used to wait until thde children have exited. */
};

struct file_descriptor {
  int id;
  struct file *file;
  struct list_elem elem;
};

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */

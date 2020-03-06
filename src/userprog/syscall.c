#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int call_number = -1;

  if (is_user_vaddr(f->esp))
  {
    // valid virtual address, read the number.
    call_number = get_user(f->esp);
  }

  printf ("system call[%d]!\n", call_number);
  thread_exit ();
}

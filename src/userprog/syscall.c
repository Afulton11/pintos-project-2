#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

void sys_write()

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
    // valid virtual address, read the sys call number.
    call_number = *(int*)get_user(f->esp);
  }

  switch (call_number)
  {
    case SYS_HALT:
    {
      break;
    }
    case SYS_EXIT:
    {
      break;
    }
    case SYS_EXEC:
    {
      break;
    }
    case SYS_WAIT:
    {
      break;
    }
    case SYS_CREATE:
    {
      break;
    }
    case SYS_REMOVE:
    {
      break;
    }
    case SYS_OPEN:
    {
      break;
    }
    case SYS_FILESIZE:
    {
      break;
    }
    case SYS_READ:
    {
      break;
    }
    case SYS_WRITE:
    {
      break;
    }
    case SYS_SEEK:
    {
      break;
    }
    case SYS_TELL:
    {
      break;
    }
    case SYS_CLOSE:
    {
      break;
    }
    default;
    {
      /* 
       * invalid pointer, safely terminate program
       * DONT KERNEL PANIC.
       * Free the processes' resources and terminate it.
       */
      break;
    }
  }

  printf ("system call[%d]!\n", call_number);
  thread_exit ();
}

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

int* get_arg(struct intr_frame *f, int number);
void set_return(struct intr_frame *f, uint32_t value);

int sys_write(int fd, const void* buffer, unsigned size);

static void syscall_handler (struct intr_frame *);
static struct file_descriptor* get_file_descriptor(struct list *descriptors, int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int call_number = -1;

  if (is_user_vaddr(f->esp))
  {
    // valid virtual address, read the sys call number.
    call_number = get_user(f->esp);
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
      int fd = get_arg(f, 1);
      void* buffer = (void*)get_arg(f, 2);
      unsigned size = (unsigned)get_arg(f, 3);

      set_return(f, sys_write(fd, buffer, size));
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
    default:
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

/*
  Gets the [i]th argument from the system call stack.
*/
int* get_arg(struct intr_frame *f, int i)
{
  return *((int*) f->esp + i);
}

/*
  Sets the return address or value for this system call.
*/
void set_return(struct intr_frame *f, uint32_t value)
{
  f->eax = value;
}

int sys_write(int fd, const void* buffer, unsigned size)
{
  ASSERT(is_user_vaddr(buffer));

  int result = 0;

  if (fd == STDOUT_FILENO)
  {
    // we should write to console output.
    // split up larger buffers (> 300 bytes)
    unsigned remaining_bytes = size;
    while (remaining_bytes > 300)
    {
      putbuf(buffer, 300);
      remaining_bytes -= 300;
    }
    putbuf(buffer, remaining_bytes);
    result = size;
  }
  else
  {
    // we should write to a file.
    struct file_descriptor *descriptor = 
        get_file_descriptor(&thread_current()->file_descriptors, fd);
    
    if (descriptor != NULL)
    {
      result = -1;
    }
  }

  return result;
}

static struct file_descriptor*
get_file_descriptor(struct list *descriptors, int fd)
{
  struct list_elem *e;

  for (e = list_begin(descriptors); 
    e != list_end(descriptors);
    e = list_next(e))
  {
    struct file_descriptor *f = list_entry(e, struct file_descriptor, elem);
    if (f->id == fd)
      return f;
  }

  return NULL;
}
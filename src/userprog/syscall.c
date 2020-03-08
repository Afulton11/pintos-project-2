#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

struct lock lock_filesys;
int get_arg(struct intr_frame *f, int number);
void set_return(struct intr_frame *f, uint32_t value);

int sys_write(int fd, const void* buffer, unsigned size);
void system_exit(int error_code);
int system_wait(pid_t pid);

static void syscall_handler (struct intr_frame *);
static struct file_descriptor* get_file_descriptor(struct list *descriptors, int fd);

void
syscall_init (void) 
{
  lock_init(&lock_filesys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int call_number = -1;

  if (f->esp != NULL && is_user_vaddr(f->esp))
  {
    // valid virtual address, read the sys call number.
    call_number = *(int*)f->esp;
  }

  switch (call_number)
  {
    case SYS_HALT: 
    {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT: 
    {
      int code = get_arg(f, 1);
      system_exit(code);

      break;
      }
    case SYS_EXEC: 
     {
       void* cmd =(void*)get_arg(f, 1);

       lock_acquire(&lock_filesys);
       pid_t pid = process_execute(cmd);
       lock_release(&lock_filesys);

       set_return(f, pid);
      break;
     }
    case SYS_WAIT: // no do
    {
      pid_t pid = get_arg(f, 1);
      set_return(f, system_wait(pid));
      break;
    }
    case SYS_CREATE:
    {
      lock_acquire(&lock_filesys);
      f->eax = filesys_create((void*)get_arg(f, 1),get_arg(f, 2));
      lock_release(&lock_filesys);
      break;
    }
    case SYS_REMOVE:
    {
      break;
    }
    case SYS_OPEN:
    {
      struct file* file;
      struct file_descriptor *fd = (struct file_descriptor*) palloc_get_page(0);
      if(!fd)
      {
        f->eax = -1;
        break;
      }

      lock_acquire(&lock_filesys);
      file=filesys_open((void*)get_arg(f, 1));

      if(!file)
      {
        palloc_free_page(fd);
        lock_release(&lock_filesys);
        f->eax = -1;
        break;
      }
      fd->file = file;
      struct list* fd_list = &thread_current()->file_descriptors;
      if(list_empty(fd_list)){
        fd->id = 3;
      }
      else{
        fd->id = (list_entry(list_back(fd_list), struct file_descriptor, elem)->id) + 1;
      }
      list_push_back(fd_list, &(fd->elem));
      lock_release(&lock_filesys);
      break;
    }
    case SYS_FILESIZE:
    {
      struct file_descriptor* fd = get_file_descriptor(&thread_current()->file_descriptors, get_arg(f, 1));

      lock_acquire(&lock_filesys);
      if(fd == NULL){
        lock_release(&lock_filesys);
        f->eax = -1;
      }
      f->eax = file_length(fd->file);
      lock_release(&lock_filesys);
      break;
    }
    case SYS_READ:
    {
      lock_acquire(&lock_filesys);
      lock_release(&lock_filesys);
      break;
    }
    case SYS_WRITE:
    {
      int fd = (int) get_arg(f, 1);
      void* buffer = (void*)(*((int*) f->esp + 2));
      unsigned size = (unsigned)get_arg(f, 3);

      set_return(f, sys_write(fd, buffer, size));
      break;
    }
    case SYS_SEEK:
    {
      struct file_descriptor* fd = 
        get_file_descriptor(&thread_current()->file_descriptors, (int)get_arg(f, 1));
      
      if(fd && fd->file){
        lock_acquire(&lock_filesys);

        file_seek(fd->file, *((unsigned*)f->esp+2));

        lock_release(&lock_filesys);
      }
      break;
    }
    case SYS_TELL:
    {
      lock_acquire(&lock_filesys);
      lock_release(&lock_filesys);
      break;
     }
    case SYS_CLOSE:
    {
      lock_acquire(&lock_filesys);
      lock_release(&lock_filesys);
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

  // printf ("system call[%d]!\n", call_number);
}

/*
  Gets the [i]th argument from the system call stack.
*/
int get_arg(struct intr_frame *f, int i)
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

void system_exit(int error_code)
{
  // we are exiting the user process safely, without halting
  printf("%s: exit(%d)\n", thread_current()->name, error_code);

  struct process_control_block *pcb = thread_current()->pcb;

  if(pcb != NULL){
    pcb->exitcode = error_code;
  }

  thread_exit();
}

int system_wait(pid_t pid)
{
  return process_wait(pid);
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
      lock_acquire(&lock_filesys);
      result = file_write(descriptor->file, buffer, size);
      lock_release(&lock_filesys);
    }
    else
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
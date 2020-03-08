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
void* get_arg_pointer(struct intr_frame *frame, int number);
void set_return(struct intr_frame *f, uint32_t value);

int sys_write(int fd, const void* buffer, unsigned size);
void system_exit(int error_code);
int system_wait(pid_t pid);

static void syscall_handler (struct intr_frame *);
static struct file_descriptor* get_file_descriptor(struct list *descriptors, int fd);
static void fail_safely(void);

void
syscall_init (void) 
{
  lock_init(&lock_filesys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
  Fail without crashing the OS, but safely exiting the process.
*/
static void fail_safely(void)
{
  if (lock_held_by_current_thread(&lock_filesys))
  {
    lock_release(&lock_filesys);
  }

  system_exit(-1);
  NOT_REACHED();
}

static void
syscall_handler (struct intr_frame *f) 
{
  int call_number = get_arg(f, 0);

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
       const char* cmd = (char*)get_arg_pointer(f, 1);

       lock_acquire(&lock_filesys);
       const pid_t pid = process_execute(cmd);
       lock_release(&lock_filesys);

       set_return(f, pid);
      break;
     }
    case SYS_WAIT:
    {
      const pid_t pid = get_arg(f, 1);
      set_return(f, system_wait(pid));
      break;
    }
    case SYS_CREATE:
    {
      const char* name = (char*)get_arg_pointer(f, 1);
      const off_t initial_size = (off_t)get_arg(f, 2);

      lock_acquire(&lock_filesys);
      const bool didCreate = filesys_create(name, initial_size);
      lock_release(&lock_filesys);

      set_return(f, didCreate);
      break;
    }
    case SYS_REMOVE:
    {
      lock_acquire(&lock_filesys);
      int r = filesys_remove(get_arg(f, 1));
      lock_release(&lock_filesys);
      set_return(f, r);
      break;
    }
    case SYS_OPEN:
    {
      struct file* file = NULL;
      struct file_descriptor *fd = (struct file_descriptor*) palloc_get_page(0);

      if(fd == NULL)
      {
        set_return(f, -1);
        break;
      }

      const char* name = (char*)get_arg_pointer(f, 1);
      lock_acquire(&lock_filesys);

      file = filesys_open(name);
      if(file == NULL)
      {
        palloc_free_page(fd);
        lock_release(&lock_filesys);
        set_return(f, -1);
        break;
      }
      fd->file = file;

      struct list *fd_list = &thread_current()->file_descriptors;
      if(list_empty(fd_list))
      {
        fd->id = STDOUT_FILENO + 1;
      }
      else
      {
        struct list_elem *last_elem = list_back(fd_list);
        struct file_descriptor *last_descriptor = list_entry(last_elem, struct file_descriptor, elem);
        fd->id = last_descriptor->id + 1;
      }

      list_push_back(fd_list, &(fd->elem));
      lock_release(&lock_filesys);
      break;
    }
    case SYS_FILESIZE:
    {
      const int fd_id = get_arg(f, 1);
      struct list *descriptor_list = &thread_current()->file_descriptors;
      struct file_descriptor* fd = get_file_descriptor(descriptor_list, fd_id);

      lock_acquire(&lock_filesys);
      if(fd == NULL)
      {
        lock_release(&lock_filesys);
        set_return(f, -1);
      }

      set_return(f, file_length(fd->file));
      lock_release(&lock_filesys);
      break;
    }
    case SYS_READ: // boi
    {
      lock_acquire(&lock_filesys);
      lock_release(&lock_filesys);
      break;
    }
    case SYS_WRITE:
    {
      int fd = (int) get_arg(f, 1);
      void* buffer = get_arg_pointer(f, 2);
      unsigned size = (unsigned)get_arg(f, 3);

      set_return(f, sys_write(fd, buffer, size));
      break;
    }
    case SYS_SEEK:
    {
      struct file_descriptor* fd = 
        get_file_descriptor(&thread_current()->file_descriptors, (int)get_arg(f, 1));
      
      if(fd != NULL && fd->file){
        lock_acquire(&lock_filesys);

        file_seek(fd->file, *((unsigned*)f->esp+2));

        lock_release(&lock_filesys);
      }
      break;
    }
    case SYS_TELL:
    {
      lock_acquire(&lock_filesys);
      struct file_descriptor* fd = get_file_descriptor(descriptor_list, get_arg(f, 1));
      if(!fd || fd->file == null){
        set_return(f, -1);
      }
      else{
        set_return(f, file_tell(fd->file))
      }
      lock_release(&lock_filesys);
      break;
     }
    case SYS_CLOSE:
    {
      lock_acquire(&lock_filesys);
      struct file_descriptor fd = get_file_descriptor(descriptor_list, get_arg(f, 1));
      file_close(fd->file);
      palloc_free_page(fd);
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
      fail_safely();
      break;
    }
  
  }

  // printf ("system call[%d]!\n", call_number);
}

/*
  Gets the [i]th argument from the system call stack, validating the location of the stack pointer.
*/
int get_arg(struct intr_frame *f, int i)
{
  if (!is_valid_user_vaddr(f->esp))
  {
    fail_safely();
  }

  return *((int*) f->esp + i);
}

/*
  Gets the [i]th argument from the system call stack,
  validating the location of the frame's stack pointer through get_arg,
  and validating the location the pointer itself.
*/
void* get_arg_pointer(struct intr_frame *frame, int arg_number)
{
  void* vaddress = (void*)get_arg(frame, arg_number);
  
  if (!is_valid_user_vaddr(vaddress))
  {
    fail_safely();
  }

  return vaddress;
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
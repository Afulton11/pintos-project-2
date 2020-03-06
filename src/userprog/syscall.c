#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
struct lock file;
void
syscall_init (void) 
{
  lock_init(&file);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int call_number = -1;

  if (is_user_vaddr(f->esp))
  {
    // valid virtual address, read the sys call number.
    call_number = get_user(f->esp);
    thread_current()->current_esp = f->esp;
  }

  switch (call_number)
  {
    case SYS_HALT: 
    {
    shutdown_power_off();
      break;
    case SYS_EXIT: 
    int code = *(int*)f->esp+1;
    struct process_control_block *pcb = thread_current()->pcb;
    if(pcb != NULL){
      pcb->exitcode = code;
      }
      thread_exit();
      break;
    }
    case SYS_EXEC: 
     {
       void* cmd =(void*)(*((int*)f->esp+1));
       lock_acquire(&file);
       pid_t pid = process_execute(cmd);
       lock_release(&file);
       f->eax = pid;
      break;
     }
    case SYS_WAIT: // no do
    {
      break;
    }
    case SYS_CREATE:
    {
      lock_acquire(&file);
      f->eax = filesys_create((void*)(*((int*)f->esp+1)),*((int*)f->esp+2));
      lock_release(&file);
      break;
    }
    case SYS_REMOVE:
    {
     if(file)
      break;
    }
    case SYS_OPEN:
    {
      
      struct file* f;
      struct file_description* fd = palloc_get_page(0);
      if(!fd){
        f->eas = -1;
        break;
      }
      lock_acquire(&file);
      f=filesys_open((void*)(*((int*)f->esp+1));
      if(!f){
        palloc_free_page(fd);
        lock_release(&file);
        f->eax = -1;
        break;
      }
      fd->file=f;
      struct list* fd_list = &thread_current()->file_descriptors;
      if(list_empty(&fd_list)){
        fd->id = 3;
      }
      else{
        fd->id = (list_entry(list_back(fd_list), struct file_descriptor, elem)->id) + 1;
      }
      list_push_back(fd_list, &(fd->elem));
      lock_release(&file);
      break;
    }
    case SYS_FILESIZE:
    {
      struct file_descriptor* fd;
      lock_acquire(&file);
      // get file descriptor from thread current
      if(fd== NULL){
        lock_release(&file);
        f->eax = -1;
      }
      f->eax = file_length(fd-file);
      lock_release(&file);
      break;
    }
    case SYS_READ:
    {
      lock_acquire(&file);
      lock_release(&file);
      break;
    }
    case SYS_WRITE: // no do
    {
      break;
    }
    case SYS_SEEK:
    {
      lock_acquire(&file);
      struct file_descriptor* fd;
      // get file descriptor from thread current
      if(fd && fd->file){
        f->eax = file_seek(fd->file, *((unsigned*)f->esp+2)
      }
      else{
        f->eax = -1;
      }
      lock_release(&file);
      break;
    }
    case SYS_TELL:
    {
      lock_acquire(&file);
      lock_release(&file);
      break;
     }
    case SYS_CLOSE:
    {
      lock_acquire(&file);
      lock_release(&file);
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

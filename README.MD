Pintos Project 2 – User Programs
===
We are starting with a completely fresh installation of pintos.

All work done for this assignment will be in the `pintos/src/userprog` directory.

# Implementing

Terminating: 
```c
if (is_user_process && !did_halt)
  printf ("%s: exit(%d)\n", name, pid);
```
### 1. Argument Passing

`process_execute()` should support passing arguments to new processes. The input
should be divided into words at spaces, multiple spaces in a row are still 1 space.

First word = program name
After first...
ith word = ith argument

Impose a limit on arguments i.e. < 4KB

use `strtok_r()` for tokenization

### 2. User Memory Access
See Accessing User Memory in Project Summary below.

### 3. Read System Calls From User Stack
See section 3.3.4 System Calls.

`userprog/syscall.c` should retrieve the system call number & system call arguments.
Then perform the actions.

We need ways to read & write data in user VA space to even obtain the sytem call number.
Here is where we check for a valid pointer from the user proc

System calls need to be synchronized so multiple user processes can make them at once.
File system code should be treated as critical section code, but don't modify filesys code.

user-level functions are provided for each system call in `lib/user/syscall.c` User processes use these to invoke each system call.

A user program shouldn't cause the OS to crash.

### 4. Exit System Call
Terminates the current user program, returning the *status* to the kernel. A status of 0 indicates success, nonzero indicates an error.

### 5. Write System Call
`write(int fileDescriptor, const void *buffer, unsigned size)`
Writes size bytes from buffer to open the fileDescriptor. Returning the number of bytes that were actually written, which is possibly less than size if some bytes could not be written.

### 6. Provide correct Impl For `process_wait()`

For the `wait()` system call:
  This should wait for a child process pid and retrieves the child's exit status. If pid still alive wait till the child terminates, then retunr the pid passed to exit. If pid was killed by the kernel, wait(pid) should return -1.

  wait should fail, returning -1 if:
    1. pid doesn't refer to a direct child of the calling process.
        * pid is only a direct child of the calling process when the calling processing received pid as a return value from a successful call to `exec`.
        * Children cannot be inherited.
    2. If a process calls wait on a pid that its already waiting on. The process can only wait for the same child once.

  Its important to realize that a process could exit before it's children, We need to account for this. All a proccess' resources should be freed regardless of if its parent is waiting for it or not.

The suggested temporary implementation of `process_wait` will be implemented first, then a more robust one once we get to it.

### 7. Denying Writes to Executables

Writes to files that are executables should be denied using `file_deny_write()` to prevent writes to an open file. `file_allow_writes()` reenables writes. 

The executable should be kept open as long as the process is running.

# Project Summary

Project 2 is about running programs in user space. These programs will be known as user programs and will not directly access the kernel, but will do so through system OS calls.

pintos has provided us a file system in `file.h` and `filesys.h`.

The following command can be used to run the `echo` program with temporary file partitioning of size **n** megabytes just for the duration of pintos' run:
```bash
pintos --filesys-size=2 -p ../../examples/echo -a echo -- -f -q run 'echo x'
```

A pintos file can be removed using *rm*:
```bash
pintos -q rm file
```

`src/examples/*` Contains example user programs. The makefile only compiles the provided example programs.

User programs will have access to virtual memory space that we will map to phyiscal memory.

### Virtual Memory in Pintos
user memory ranges from 0 to *PHYS_BASE*, defined in `threads/vaddr.h` default is 3 GB. Kernel memory is in the rest of the virtual address space, up to 4 GB.

pintos will switch user virtual address spaces by changing the processors' Page Directory Base Register (`pagedir_activate() in userprog/pagedir.c`)

kernel virtual memory is global, and always mapped in the same way to every user/kernel process. Kernel virtual memory is mapped 1 to 1, Virtual address (VA) *PHYS_BASE* accesses physical address (PA) 0, VA *PHYS_BASE* + 0x1234 accesses PA 0x1234, and so on.

A user program can only access its own virtual memory, any attempt to access memory outside (including kernel memory) will result in a page_fault().

Pintos code segment starts at user VA `0x08084000`, 128 MB from the bottom of the address space.

### Accessing User Memory
The kernel often accesses memory through pointers provided by a user programn. The kernel must make sure the pointer (in VA space) is: 
  * not *NULL*
  * not a pointer to unmapped VA space
  * not a pointer to kernel VA space (i.e. above PHYS_BASE)

otherwise, the pointer is invalid. Invalid pointers should be rejected without harming the running process or kernel. This rejection can be done by terminating the process and freeing its resources.

2 ways to interpret VA pointers:
  1. verify validity of pointer then dereference it. See functions in `userprog/pagedir.c` and `threads/vaddr.h` if this method is chose
  2. Check the user pointer points to space below PHYS_BASE, then derefernce it. The invalid pointer will cause a pauge_fault() in `userprog/exception.c` and is generally faster, taking advantage of the processor's MMU.

In both cases, make sure not to leak resources by making sure to release locks or free pages of memory after encountering an invalid user pointer. This is more difficult to handle if the invalid pointer causes a page fault. Therefore if you choose the second option here's helpful code for handling it:
```C
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault occurred. */
static int
get_user (const uint8_t *uaddr) {
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst): "q" (byte)); 
  return error_code != -1;
}
```

The above code works assuming that the user address has already been verified to be below the PHYS_BASE AND that you've modified `page_fault()` so that a page fault in the kernel sets `eax` to `0xffffffff`, copying the former value of eax into `eip`.

### Useful Documentation
  1. [Stanford Project 2 Reference](https://web.stanford.edu/class/cs140/projects/pintos/pintos_3.html#SEC32)
  2. [Dr. Andresen Project 2](https://k-state.instructure.com/courses/85470/files/folder/Projects?preview=12771783)
  3. Chapters 8 - 12 in **Operating System Concepts *Essentials* Textbook**
  4. [Slides Ch. 8 - 12](https://k-state.instructure.com/courses/85470/files/folder/Lectures?)
      * Chapter 8: **Main Memory**
      * Chapter 9: **Virtual Memory**
      * Chapter 10: **Mass-Storage Systems**
      * Chapter 11: **File-System Interface**
      * Chapter 12: **File-System Implementation**
  5. [Stanford Docs PDF Format](https://web.stanford.edu/class/cs140/projects/pintos/pintos.pdf)
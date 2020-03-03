Pintos Project 2 – User Programs
===
We are starting with a completely fresh installation of pintos.

All work done for this assignment will be in the `pintos/src/userprog` directory.

Project Summary
---
Project 2 is about running programs in user space. These programs will be known as user programs and will not directly access the kernel, but will do so through system OS calls.

pintos has provided us a file system in `file.h` and `filesys.h`.

The following command can be used to run the `echo` program with temporary file partiong of size **n** megabytes just for the duration of pintos' run:
```bash
pintos --filesys-size=2 -p ../../examples/echo -a echo -- -f -q run 'echo x'
```

A pintos file can be removed using *rm*:
```bash
pintos -q rm file
```

`src/examples/*` Contains example user programs. The makefile only compiles the provided example programs.

User programs will have access to virtual memory space that we will map to phyiscal memory.

## Our Implementation...

TODO

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
       : "=&a" (result) : "m" (*uaddr)); return result;
}
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst): "q" (byte)); return error_code != -1;
}
```

The above code works assuming that the user address has already been verified to be below the PHYS_BASE AND that you've modified `page_fault()` so that a page fault in the kernel sets eax to 0xffffffff and copies the former value of eax into eip.

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
# Nines (9S) - POC


This project is result of an experimention on code injection techniques on the PlayStation 5, since it's not possible to allocate executable memory with calls like `mmap` and other techniques like abusing `JIT` memory area to write shellcode into is not available to every process.


## Idea

The idea is rather simple, with Kernel R/W primitives into the `.data` section one is possible to elevate process specific privileges, such the AuthorityID which give ability to debug other processes with `ptrace`, with this power in hand is possible to invoke remote functions to load a library inside the process, with good space of executable memory area.

After loaded, one can remove all the existing data and write a shellcode or load a ELF file into it. It's similar to the Windows Process Hollowing technique. 

In order to trigger the shellcode, we remotly resolve and call the function `pthread_create` to initialize the shellcode.


## Resources


- [John Törnblom amazing SDK](https://github.com/ps5-payload-dev/sdk)
- [PS5 gdb server project](https://github.com/ps5-payload-dev/gdbsrv)



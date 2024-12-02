#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/proc.h"
#include "../include/ucred.h"
#include "../include/injector.h"

#include "ps5/mdbg.h"

#include <dlfcn.h>

#define DUMP_SIZE 0x100

int main(int argc, char const *argv[])
{
    struct proc* target_proc = find_proc_by_name("SceShellUI");
    if (target_proc)
    {
        // puts("LISTANDO MODULOS!!!!");
        // list_proc_modules(target_proc);
        inject_elf(target_proc);
    }       

    return 0;
}

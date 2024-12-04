#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/proc.h"
#include "../include/ucred.h"
#include "../include/injector.h"
#include "../include/notify.h"
#include "../include/server.h"

#include "ps5/mdbg.h"

#include <dlfcn.h>

#define DUMP_SIZE 0x100

#define PORT 9030


void inject(int incoming_fd, void* data, ssize_t data_size)
{

}

int main(int argc, char const *argv[])
{

    if (!start_server(PORT, inject))
    {
        notify_send("Unable to initialize injector server on port %d! Aborting...", PORT);
        return 1;
    }


    struct proc* target_proc = find_proc_by_name("SceShellUI");
    if (target_proc)
    {
        // puts("LISTANDO MODULOS!!!!");
        // list_proc_modules(target_proc);
        inject_elf(target_proc);
    }       

    return 0;
}

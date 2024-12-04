#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <elf.h>
#include <signal.h>

#include "../include/proc.h"
#include "../include/ucred.h"
#include "../include/injector.h"
#include "../include/notify.h"
#include "../include/server.h"

#include "ps5/mdbg.h"

#include <dlfcn.h>

#define DUMP_SIZE 0x100
#define MAX_PROC_NAME 0x100
#define PORT 9033
#define THREAD_NAME "injector.elf"

typedef struct __injector_data_t
{
    char proc_name[MAX_PROC_NAME];
    Elf64_Ehdr elf_header;
} injector_data_t;


#if __BYTE_ORDER == __ORDER_LITTLE_ENDIAN__
	uint32_t elf_magic = 0x464c457f;
#else
	uint32_t elf_magic = 0x7f454c46;
#endif 


//
// Callback used for every requested injection
//
void inject(int incoming_fd, void* data, ssize_t data_size)
{   
    if (data_size < sizeof(injector_data_t))
    {
        printf("Invalid injection request received!\n");
        return;
    }
    
    injector_data_t* injection_data = (injector_data_t*) data;
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*) &injection_data->elf_header;
    
    printf("Injecting on %s...\n", injection_data->proc_name);

    struct proc* target_proc = find_proc_by_name(injection_data->proc_name);

    if (target_proc)
    {
        if (inject_elf(target_proc, elf_header))
        {
            notify_send("ELF Injected successfully on %s!\n", target_proc->p_comm);
        }

        free(target_proc);
    }
}


int main(int argc, char const *argv[])
{
    struct proc* existing_instance = find_proc_by_name(THREAD_NAME);
    
    if (existing_instance)
    {
        if (kill(existing_instance->pid, SIGKILL))
        {
            printf("Unable to kill %d\n", existing_instance->pid);
            return 1;
        }
    }

    syscall(SYS_thr_set_name, -1, THREAD_NAME);
    notify_send("Starting injector on %d...", PORT);

    if (start_server(PORT, inject) <= 0)
    {
        notify_send("Unable to initialize injector server on port %d! Aborting...", PORT);
        return 1;
    }

    return 0;
}

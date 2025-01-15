#include "../include/injector.h"

int attached = false;
intptr_t remote_malloc = 0;
intptr_t remote_pthread_create = 0;
void* remote_pthread_join = NULL;
SCEFunctions sce_functions = {0};


//
// Shellcode used for debugging, not so useful for ELF loading
//
int __attribute__((section(".stager_shellcode$1")))  stager(SCEFunctions* functions)
{
    pthread_t thread;
    functions->pthread_create_ptr(&thread, 0, (void *(*)(void *)) functions->elf_main, functions->payload_args);

    asm("int3");

    return 0;
}

//
// Just used to calculate stager size
//
int __attribute__((section(".stager_shellcode$2"))) stager_end()
{
    return 0;
}

//
// Poor man function size counter, temp stuff
//
uint32_t get_shellcode_size()
{
    return &stager_end - &stager;
}   


//
// Init all remote function pointers needed for injection
//
void init_remote_function_pointers(pid_t pid)
{
    if (!attached)
    {
        if (pt_attach(pid) < 0)
        {
            printf("Error attaching PID %d! aborting...\n", pid);
            return;
        }
    }

    char nid[12] = {0};
    //
    // Injector/loader specifics
    //
    nid_encode("malloc", nid);
    remote_malloc = pt_resolve(pid, nid);
    nid_encode("pthread_create", nid);
    remote_pthread_create = pt_resolve(pid, nid);
    nid_encode("nid_pthread_join", nid);
    remote_pthread_join = (void*) pt_resolve(pid, nid);

    //
    // Shellcode function pointers
    //
    nid_encode("sceKernelDebugOutText", nid);
    sce_functions.sceKernelDebugOutText = (void*) pt_resolve(pid, nid);
    sce_functions.pthread_create_ptr = (void*) remote_pthread_create;



}


int inject_elf(struct proc* proc, void* elf)
{   
    puts("[+] Elevating injector...[+]\n");

    set_ucred_to_debugger();
    int status = true;
    uint64_t sce_ptr_mem;
    uint64_t shellcode_size = get_shellcode_size();
    uint8_t* original_code = malloc(shellcode_size);

    if (pt_attach(proc->pid) < 0)
    {
        printf("Error attaching into PID: %d\n", proc->pid);
        status = false;
        goto exit;
    }

    printf("[+] Attached to %d! [+]\n", proc->pid);
    attached = true;

    init_remote_function_pointers(proc->pid);

    printf("[+] Loading ELF on %d...[+]\n", proc->pid);
    intptr_t entry = elfldr_load(proc->pid, (uint8_t*) elf);

    if (entry <= 0)
    {
        printf("[-] Failed to load ELF! [-]\n");
        goto detach;
    }

    intptr_t args = elfldr_payload_args(proc->pid);
    printf("[+] ELF entrypoint: %#02lx [+]\n[+] Payload Args: %#02lx [+]\n", entry, args);

    //  
    // Copy shellcode thread parameters
    //
    
    module_info_t* mod = get_module_handle(proc->pid, "eboot.bin");
    sce_functions.elf_main = (void*) entry;
    sce_functions.payload_args = (void*) args;

    //
    // Store original .init code and overwrite with the stager
    //
    mdbg_copyout(proc->pid, mod->init, original_code, shellcode_size);
    mdbg_copyin(proc->pid, stager, mod->init, shellcode_size);
    //
    // Write the sce functions data
    //
    sce_ptr_mem = pt_call(proc->pid, remote_malloc, sizeof(SCEFunctions));
    mdbg_copyin(proc->pid, &sce_functions, sce_ptr_mem, sizeof(SCEFunctions));

    puts("[+] Triggering entrypoint... [+]\n");
    //
    // Call until hit a breakpoint
    //
    pt_call2(proc->pid, mod->init, sce_ptr_mem);
    // mdbg_copyin(proc->pid, original_code, mod->init, shellcode_size);

    pt_detach(proc->pid);

    puts("[+] ELF injection finished! [+]");
    //
    // Restore stager
    //

detach:
    puts("[+] Detached [+]");
exit:
    return status;

}

//
// We can't stuck sceshellui for too long or the system will kill it's process, so we will load the library in a separated thread
//
module_info_t* load_remote_library(pid_t pid, const char* library_path, const char* library_name)
{
    if (!attached)
    {
        if (pt_attach(pid) < 0)
        {
            printf("load_remote_library: Failed to attach PID %d\n", pid);
            return NULL;
        }
    }

    // intptr_t library_str = pt_call(pid, 0, 0x100, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    intptr_t library_str = pt_call(pid, remote_malloc, strlen(library_name) + 1);
    mdbg_copyin(pid, library_path, library_str, strlen(library_path) + 1);

    //
    // Run the module loading in a separated thread
    //
    intptr_t sce_kernel_load_start_module = pt_resolve(pid, nid_sce_kernel_load_start_module);
    create_remote_thread(pid, sce_kernel_load_start_module, library_str);

    printf("sce_kernel_load_start_module: %#02lx\n", sce_kernel_load_start_module);
    //
    // Now we detach, sleep a little and attach again
    //
    pt_detach(pid);

    int retries = 0;
    int max_retries = 100;
    module_info_t* module = NULL;

    while (retries <= max_retries)
    {
        module = get_module_handle(pid, library_name);
        if (!module)
        {
            usleep(500);
        } else
        {
            break;
        }
        retries++;
    }
    
    if (!module)
    {
        printf("Unable to load %s into PID %d!\n", library_name, pid);
    }

    pt_attach(pid);

    return module;
}


int create_remote_thread(pid_t pid, uintptr_t target_address, uintptr_t parameters)
{
    if (!attached)
    {
        if (pt_attach(pid) < 0)
        {
            printf("Unable to attach into the remote process!\n");
            return false;
        }
    }

    intptr_t pthread = pt_call(pid, remote_malloc, sizeof(pthread_t));
    if (!pthread)
    {
        printf("Unable to allocate memory for pthread pointer!\n");
        return false;
    }

    //
    // We don't have to wait (join), otherwise we would block the whole target
    //
    return pt_call(pid, remote_pthread_create, pthread, 0, target_address, parameters);
}





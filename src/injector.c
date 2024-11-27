#include "../include/injector.h"

int attached = false;
void* remote_malloc = NULL;
void* remote_pthread_create = NULL;
void* remote_pthread_join = NULL;
SCEFunctions sce_functions = {0};


int __attribute__((section(".stager_shellcode$1")))  stager(SCEFunctions* functions)
{
    
    char hello[6]; //;= {'h', 'e', 'l', 'l', 'o', '\n'};
    hello[0] = 'h';
    hello[1] = 'e';
    hello[2] = 'l';
    hello[3] = 'l';
    hello[4] = 'o';
    hello[5] = '\n';

    functions->sceKernelDebugOutText(0, hello); 

    return 100;
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
    //
    // Injector/loader specifics
    //
    remote_pthread_create = (void*) pt_resolve(pid, nid_pthread_create);
    remote_pthread_join = (void*) pt_resolve(pid, nid_pthread_join);

    //
    // Shellcode function pointers
    //

    char nid[12];
    nid_encode("sceKernelDebugOutText", nid);
    sce_functions.sceKernelDebugOutText = (void*) pt_resolve(pid, nid);

}


int write_parasite_loader(struct proc* proc)
{
    int status = true;
    if (pt_attach(proc->pid) < 0)
    {
        printf("Error attaching into PID: %d\n", proc->pid);
        status = false;
        goto exit;
    }

    attached = true;

    init_remote_function_pointers(proc->pid);

    printf("Loading "TARGET_SPRX" inside PID %d...\n", proc->pid);
    module_info_t* module = load_remote_library(proc->pid, TARGET_SPRX, TARGET_SPRX_BASENAME);

    if (!module)
    {
        printf("Unable to load "TARGET_SPRX" Into the target process!, aborting...\n");
        list_proc_modules(proc);
        status = false;
        goto detach;
    }

    printf("Found " TARGET_SPRX_BASENAME", starting module hollowing...\n");

    //
    // Hollow the module
    //

    module_section_t* text_section = NULL;
    
    for (ssize_t i = 0; i < MODULE_INFO_MAX_SECTIONS; ++i)
    {

        if (module->sections[i].prot & PROT_EXEC)
        {
            text_section = &module->sections[i];
            printf(".text => %#02lx available space %lu bytes!\n", text_section->vaddr, text_section->size);
        }

        printf("Nuking section %#02lx\n", module->sections[i].vaddr);
        uint8_t* nuke_buff = (uint8_t*) malloc(module->sections[i].size);
        memset(nuke_buff, 0xCC, module->sections[i].size);
        mdbg_copyin(proc->pid, nuke_buff, module->sections[i].vaddr, module->sections[i].size);
        free(nuke_buff);
    }


    if (!text_section)
    {
        printf("Unable to find .text section! Aborting...\n");
        goto clean;
    }


    //
    // Copy shellcode
    //
    
    printf("Copying shellcode to %#02lx...\n", text_section->vaddr);
    mdbg_copyin(proc->pid, stager, text_section->vaddr, get_shellcode_size());

    //
    // Copy shellcode thread parameters
    //

    intptr_t remote_sce_functions = pt_mmap(proc->pid, 0, sizeof(SCEFunctions), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mdbg_copyin(proc->pid, &sce_functions, remote_sce_functions, sizeof(sce_functions));

    puts("Triggering shellcode...");
    //
    // Create a thread inside the target process
    // 
    create_remote_thread(proc->pid, text_section->vaddr, remote_sce_functions);


clean:
    free(module);

detach:
    pt_detach(proc->pid);

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

    intptr_t library_str = pt_mmap(pid, 0, 0x100, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    mdbg_copyin(pid, library_path, library_str, strlen(library_path) + 1);

    //
    // Run the module loading in a separated thread
    //
    intptr_t sce_kernel_load_start_module = pt_resolve(pid, nid_sce_kernel_load_start_module);
    create_remote_thread(pid, sce_kernel_load_start_module, library_str);
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


    void* pthread = (void*) pt_mmap(pid, 0, sizeof(pthread_t), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (!pthread)
    {
        printf("Unable to allocate memory for pthread pointer!\n");
        return false;
    }

    //
    // Create remote thread
    //
    
    pt_call(pid, (intptr_t) remote_pthread_create, pthread, NULL, target_address, parameters);
    printf("Created remote thread at %#02lx\n", target_address);
    //
    // Done, we don't have to wait (join)
    //
    return true;
}





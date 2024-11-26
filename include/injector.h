#pragma once

#include "proc.h"
#include "pt.h"
#include "ps5/mdbg.h"
#include "ps5/nid.h"
#include "nid.h"

#include <stdbool.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pthread.h>

//
// TODO: Choose a better candidate (Maybe ?) this one has at least 2MB of free exec mem space
//
#define TARGET_SPRX "libicu.sprx"


typedef struct __scefunctions
{
    int (*sceKernelDebugOutText)(int channel, const char *msg);
    // int (*sceKernelLoadStartModule)(const char *module_file_name, int args, const void *argp, int flags, void *opt, int *pRes);    

} SCEFunctions;


extern int attached;
extern SCEFunctions sce_functions;
extern void* remote_pthread_create;
extern void* remote_pthread_join;

int stager(SCEFunctions* functions);
uint32_t get_shellcode_size();
//
// Loader specifics
//
int write_parasite_loader(struct proc* proc);
int create_remote_thread(pid_t pid, uintptr_t target_address, uintptr_t parameters);
void init_remote_function_pointers(pid_t pid);
// void shellcode_start(pid_t pid, uint64_t target_address);




#pragma once

#include <stdint.h>
#include <unistd.h>
#define _KERNEL
#include <sys/ucred.h>
#undef _KERNEL

#include "proc.h"

#define DEBUG_AUTHID 0x4800000000000006
#define PTRACE_AUTHID    0x4800000000010003
#define UCRED_AUTHID_KERNEL_OFFSET
#define UCRED_SIZE 0x200


struct proc_creds
{
    uint8_t ucred[UCRED_SIZE];
    intptr_t original_rootdir;
};

// uintptr_t get_current_ucred();
void set_ucred_to_debugger();
struct proc_creds* jailbreak_process(pid_t pid);
void jail_process(pid_t pid, struct proc_creds* old_ucred);

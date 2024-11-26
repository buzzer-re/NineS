#include "../include/ucred.h"


//
// Search process entr on the allproc linked list
// acquire the "ucred" structure and elevate it
//
void set_ucred_to_debugger()
{
    struct proc* proc = get_proc_by_pid(getpid());

    if (proc)
    {
        //
        // Parse process ucred
        //
        struct ucred ucred;
        bzero(&ucred, sizeof(struct ucred));
        //
        // Read from kernel
        //
        uintptr_t authid = 0;
        uintptr_t ptrace_authid = PTRACE_AUTHID;
        kernel_copyout((uintptr_t) proc->p_ucred + 0x58, &authid, sizeof(uintptr_t));

        kernel_copyin(&ptrace_authid, (uintptr_t) proc->p_ucred + 0x58, sizeof(uintptr_t));

        free(proc);
    }
}



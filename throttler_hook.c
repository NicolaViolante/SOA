#include <linux/module.h>
#include <linux/mutex.h>
#include "throttler_internal.h"

int monitored_syscalls[NR_syscalls] = {0};
long (*original_sys_funcs[NR_syscalls])(const struct pt_regs *);
DEFINE_MUTEX(hook_mutex);
        

int hook_syscall(int nr) {
    unsigned long cr0;
    unsigned long cr4;
    
    if (nr < 0 || nr >= NR_syscalls) {
        pr_err("THROTTLER: Invalid syscall number %d\n", nr);
        return -EINVAL;
    }
    mutex_lock(&hook_mutex);
    if (monitored_syscalls[nr]) {
        mutex_unlock(&hook_mutex);
        pr_warn("THROTTLER: Syscall %d is already hooked\n", nr);
        return -EEXIST;
    }
    begin_syscall_table_hack(&cr0,&cr4); //hack per permettere scrittura sulla memoria
    
    original_sys_funcs[nr] = (void *)hacked_syscall_tbl[nr]; //salvataggio indirizzo originale
    hacked_syscall_tbl[nr] = (unsigned long *)universal_syscall_wrapper; //sovrascrittura puntatore con indirizzo wrapper
    monitored_syscalls[nr] = 1; //inserimento system call tra quelle monitorate
    
    end_syscall_table_hack(cr0,cr4);
    mutex_unlock(&hook_mutex);
    pr_info("THROTTLER: Successfully hooked syscall %d\n", nr);
    return 0;
}

int throttler_unhook_syscall(int nr) {
    unsigned long cr0;
    unsigned long cr4;
    
    if (nr < 0 || nr >= NR_syscalls) {
      pr_err("THROTTLER: Invalid syscall number %d\n", nr);
      return -EINVAL;
      }
    mutex_lock(&hook_mutex);
    if (!monitored_syscalls[nr]) {
        mutex_unlock(&hook_mutex);
        pr_warn("THROTTLER: Cannot unhook syscall %d - Not monitored\n", nr);
        return -ENOENT; 
    }
    if (!original_sys_funcs[nr]) {
        mutex_unlock(&hook_mutex);
        pr_err("THROTTLER: No original function for hooked syscall %d!\n", nr);
        return -EFAULT;
    }
    begin_syscall_table_hack(&cr0,&cr4);
    
    hacked_syscall_tbl[nr] = (unsigned long *)original_sys_funcs[nr];
    monitored_syscalls[nr] = 0;
    
    original_sys_funcs[nr] = NULL;
    
    end_syscall_table_hack(cr0,cr4);
    
    mutex_unlock(&hook_mutex);
    pr_info("THROTTLER: Successfully unhooked syscall %d\n", nr);
    return 0;
}

int hook_all_syscalls(void) {
    int i;
    int success_count = 0;
    
    for (i = 0; i < NR_syscalls; i++) {
        if (hook_syscall(i) == 0) {
            success_count++;
        }
    }
    pr_info("THROTTLER: Hooked %d/%d syscalls\n", success_count, NR_syscalls);
    return success_count;
}

int unhook_all_syscalls(void) {
    int i;
    int success_count = 0;
    int fail_count = 0;
    
    for (i = 0; i < NR_syscalls; i++) {
        if (monitored_syscalls[i]) {
            if (throttler_unhook_syscall(i) == 0) {
                success_count++;
            } else {
                fail_count++;
            }
        }
    }
    if (fail_count > 0) {
        pr_err("THROTTLER: Failed to unhook %d syscalls! (Successfully unhooked: %d)\n", fail_count, success_count);
    } else {
        pr_info("THROTTLER: Successfully unhooked all %d monitored syscalls\n", success_count);
    }
    return fail_count;
}

int throttler_get_syscalls(int *k_buf, int max) {
    int i;
    int count = 0;

    if (!k_buf || max <= 0) {
        return -EINVAL;
    }
    for (i = 0; i < NR_syscalls; i++) {
        if (monitored_syscalls[i]) {
            if (count >= max) break;
            k_buf[count] = i;
            count++;
        }
    }
    return count;
}

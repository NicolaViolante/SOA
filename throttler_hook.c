#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/bitmap.h>
#include "throttler_internal.h"

DECLARE_BITMAP(monitored_syscalls, NR_syscalls) = {0};
long (*original_sys_funcs[NR_syscalls])(const struct pt_regs *);
DEFINE_MUTEX(hook_mutex);
        

int hook_syscall(int nr) {
    unsigned long cr0;
    unsigned long cr4;
    
    if (nr < 0 || nr >= NR_syscalls) {
        pr_err("%s: Invalid syscall number %d\n",MODNAME, nr);
        return -EINVAL;
    }
    mutex_lock(&hook_mutex);
    if (test_bit(nr, monitored_syscalls)) {
        mutex_unlock(&hook_mutex);
        pr_warn("%s: Syscall %d is already hooked\n", MODNAME,nr);
        return -EEXIST;
    }
    begin_syscall_table_hack(&cr0,&cr4); //hack per permettere scrittura sulla memoria
    
    original_sys_funcs[nr] = (void *)hacked_syscall_tbl[nr]; //salvataggio indirizzo originale
    hacked_syscall_tbl[nr] = (unsigned long *)universal_syscall_wrapper; //sovrascrittura puntatore con indirizzo wrapper
    set_bit(nr, monitored_syscalls); //inserimento system call tra quelle monitorate
    
    end_syscall_table_hack(cr0,cr4);
    mutex_unlock(&hook_mutex);
    pr_info("%s: Successfully hooked syscall %d\n",MODNAME, nr);
    return 0;
}

int throttler_unhook_syscall(int nr) {
    unsigned long cr0;
    unsigned long cr4;
    
    if (nr < 0 || nr >= NR_syscalls) {
      pr_err("%s: Invalid syscall number %d\n", MODNAME,nr);
      return -EINVAL;
      }
    mutex_lock(&hook_mutex);
    if (!test_bit(nr, monitored_syscalls)) {
        mutex_unlock(&hook_mutex);
        pr_warn("%s: Cannot unhook syscall %d - Not monitored\n",MODNAME, nr);
        return -ENOENT; 
    }
    if (!original_sys_funcs[nr]) {
        mutex_unlock(&hook_mutex);
        pr_err("%s: No original function for hooked syscall %d!\n",MODNAME, nr);
        return -EFAULT;
    }
    begin_syscall_table_hack(&cr0,&cr4);
    
    hacked_syscall_tbl[nr] = (unsigned long *)original_sys_funcs[nr];
    clear_bit(nr, monitored_syscalls);
    
    original_sys_funcs[nr] = NULL;
    
    end_syscall_table_hack(cr0,cr4);
    
    mutex_unlock(&hook_mutex);
    pr_info("%s: Successfully unhooked syscall %d\n",MODNAME, nr);
    return 0;
}

int unhook_all_syscalls(void) {
    int i;
    int success_count = 0;
    int fail_count = 0;
    
    for (i = 0; i < NR_syscalls; i++) {
        if (test_bit(i, monitored_syscalls)) {
            if (throttler_unhook_syscall(i) == 0) {
                success_count++;
            } else {
                fail_count++;
            }
        }
    }
    if (fail_count > 0) {
        pr_err("%s: Failed to unhook %d syscalls! (Successfully unhooked: %d)\n", MODNAME, fail_count, success_count);
    } else {
        pr_info("%s: Successfully unhooked all %d monitored syscalls\n",MODNAME, success_count);
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
        if (test_bit(i, monitored_syscalls)) {
            if (count >= max) break;
            k_buf[count] = i;
            count++;
        }
    }
    return count;
}

#include <linux/module.h>
#include "throttler_internal.h"

int monitored_syscalls[NR_syscalls] = {0};
long (*original_sys_funcs[NR_syscalls])(const struct pt_regs *);


void hook_syscall(int nr) {
    if (nr < 0 || nr >= NR_syscalls || monitored_syscalls[nr]) return;
    
    begin_syscall_table_hack();
    original_sys_funcs[nr] = (void *)hacked_syscall_tbl[nr];
    hacked_syscall_tbl[nr] = (unsigned long *)universal_syscall_wrapper;
    monitored_syscalls[nr] = 1;
    end_syscall_table_hack();
}

int throttler_unhook_syscall(int nr) {
    if (nr < 0 || nr >= NR_syscalls) return -EINVAL;
    
    begin_syscall_table_hack();
    if (monitored_syscalls[nr] && original_sys_funcs[nr]) {
        hacked_syscall_tbl[nr] = (unsigned long *)original_sys_funcs[nr];
        monitored_syscalls[nr] = 0;
    }
    end_syscall_table_hack();
    return 0;
}

void hook_all_syscalls(void) {
    int i;
    begin_syscall_table_hack();
    for (i = 0; i < NR_syscalls; i++) {
        if (hacked_syscall_tbl[i] && hacked_syscall_tbl[i] != (unsigned long *)universal_syscall_wrapper) {
            original_sys_funcs[i] = (void *)hacked_syscall_tbl[i];
            hacked_syscall_tbl[i] = (unsigned long *)universal_syscall_wrapper;
            monitored_syscalls[i] = 1;
        }
    }
    end_syscall_table_hack();
}

void unhook_all_syscalls(void) {
    int i;
    begin_syscall_table_hack();
    for (i = 0; i < NR_syscalls; i++) {
        if (monitored_syscalls[i] && original_sys_funcs[i]) {
            hacked_syscall_tbl[i] = (unsigned long *)original_sys_funcs[i];
            monitored_syscalls[i] = 0;
        }
    }
    end_syscall_table_hack();
}

int throttler_get_syscalls(int *buf, int max) {
    int i, count = 0;
    if (!buf || max <= 0) return -EINVAL;
    
    for (i = 0; i < NR_syscalls; i++) {
        if (monitored_syscalls[i]) {
            if (count >= max) break;
            buf[count++] = i;
        }
    }
    return count;
}

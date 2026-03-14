#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h> 
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/module.h>

#include "throttler_ioctl.h"
#include "throttler_internal.h"

long throttler_ioctl_dispatcher(struct file *file, unsigned int cmd, unsigned long arg) {
    int value;
    int rc;
    char prog_name[TASK_COMM_LEN];
    int *k_sys;
    int count;
    bool is_read_cmd = false;

    uid_t *k_uids;
    char (*k_progs)[TASK_COMM_LEN];
    
    //controllo se comando leggerà solamente o andrà a modificare il comportamento del modulo
    if (_IOC_DIR(cmd) & _IOC_READ) {
    is_read_cmd = true;
    }
    
    if (!is_read_cmd && current_euid().val != 0) { // se non è un comando di letture e non si è root warning
        pr_warn("%s-DEV: Access denied (EUID %u). Only root can modify monitor.\n", MODNAME, current_euid().val);
        return -EPERM;
    }
    
    if (_IOC_TYPE(cmd) != THROTTLER_IOC_MAGIC) return -ENOTTY;

    switch (cmd) {
        case THROTTLER_IOC_MONITOR_ON:
            atomic_set(&monitor_on, 1); //imposta atomicamente valore monitor ad 1 per accenderlo
            pr_info("%s-DEV: Monitor activated\n", MODNAME);
            return 0;

        case THROTTLER_IOC_MONITOR_OFF:
            atomic_set(&monitor_on, 0); //imposta atomicamente valore monitor ad 0 per spegnerlo
            pr_info("%s-DEV: Monitor deactivated\n", MODNAME);
            wake_up_all(&throttle_wq); // allo spegnimento bisogna svuotare la waitqueue
            throttler_reset_stats(); // azzeramento statistiche per prossima accensione
            return 0;

        case THROTTLER_IOC_SET_MAX:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT; //bad address in caso di fallimento
            if (value <= 0) return -EINVAL;
            max_syscalls_per_sec = value; // imposta valore passato da user space
            pr_info("%s-DEV: Max syscalls/sec: %d\n",MODNAME, value);
            return 0;

        case THROTTLER_IOC_ADD_SYSCALL:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            if (value < 0 || value >= NR_syscalls) {
              pr_err("%s: Invalid syscall number %d\n", MODNAME, value);
              return -EINVAL;
              }
            pr_info("%s-DEV: Syscall number %d will be monitored\n",MODNAME, value);
            return hook_syscall(value); //chiama funzione che altera la system call table alla entry specificata

        case THROTTLER_IOC_REMOVE_SYSCALL:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            if (value < 0 || value >= NR_syscalls) {
              pr_err("%s-DEV: Invalid syscall number %d\n", MODNAME, value);
              return -EINVAL;
            }
            pr_info("%s-DEV: Syscall number %d will not be monitored anymore\n", MODNAME, value);
            return throttler_unhook_syscall(value); //chiama funzione che ripristina la system call table alla entry specificata

        case THROTTLER_IOC_ADD_UID:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            pr_info("%s-DEV: User ID %d will be monitored\n",MODNAME, value);
            return throttler_add_uid((uid_t)value); // aggiunge valore alla lista RCU

        case THROTTLER_IOC_REMOVE_UID:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            pr_info("%s-DEV: User ID %d will not be monitored anymore\n", MODNAME, value);
            return throttler_remove_uid((uid_t)value); // rimuove valore dalla lista RCU

        case THROTTLER_IOC_ADD_PROG:
            if (copy_from_user(prog_name, (char __user *)arg, TASK_COMM_LEN)) return -EFAULT;
            prog_name[TASK_COMM_LEN-1] = '\0';
            if (strlen(prog_name) == 0) return -EINVAL;
            pr_info("%s-DEV: Program %s will be monitored\n", MODNAME, prog_name);
            return throttler_add_prog(prog_name);

        case THROTTLER_IOC_REMOVE_PROG:
            if (copy_from_user(prog_name, (char __user *)arg, TASK_COMM_LEN)) return -EFAULT;
            prog_name[TASK_COMM_LEN-1] = '\0';
            if (strlen(prog_name) == 0) return -EINVAL;
            pr_info("%s-DEV: Program %s will not be monitored anymore\n", MODNAME, prog_name);
            return throttler_remove_prog(prog_name);

        case THROTTLER_IOC_GET_PEAK_DELAY:
        case THROTTLER_IOC_GET_PEAK_DELAY_INFO:
        case THROTTLER_IOC_GET_PEAK_BLOCKED: {
            int cpu;
            unsigned long global_peak_ns = 0;
            int global_peak_blocked = 0;
            struct throttler_peak_info global_peak_info;
            memset(&global_peak_info, 0, sizeof(struct throttler_peak_info));
            
            for_each_possible_cpu(cpu) {
                struct throttler_stats *st = &per_cpu(local_stats, cpu); // puntatore alle statistiche dell'iesima CPU
                
                if (st->peak_delay_ns > global_peak_ns) { // controllo se picco di ritardo registrato dalla specifica CPU è il più grande 
                    global_peak_ns = st->peak_delay_ns;
                    global_peak_info.uid = st->peak_delay_uid;
                    strscpy(global_peak_info.prog, st->peak_delay_prog, sizeof(global_peak_info.prog));
                    }
                if (st->peak_blocked_threads > global_peak_blocked) { // controllo se picco di thread bloccati registrato dalla specifica CPU è il più grande 
                    global_peak_blocked = st->peak_blocked_threads;
                }
            }

            if (cmd == THROTTLER_IOC_GET_PEAK_DELAY) {
                if (copy_to_user((unsigned long __user *)arg, &global_peak_ns, sizeof(unsigned long))) return -EFAULT;
            } else if (cmd == THROTTLER_IOC_GET_PEAK_DELAY_INFO) {
                if (copy_to_user((void __user *)arg, &global_peak_info, sizeof(struct throttler_peak_info))) return -EFAULT;
            } else if (cmd == THROTTLER_IOC_GET_PEAK_BLOCKED) {
                if (copy_to_user((int __user *)arg, &global_peak_blocked, sizeof(int))) return -EFAULT;
            }
            return 0;
        }

        case THROTTLER_IOC_GET_AVG_BLOCKED: {
            int cpu;
            unsigned long global_total_samples = 0; //thread bloccati
            unsigned long global_count = 0; //numero campionamenti
            struct throttler_avg_data avg_data; // struttura per restituire risultati in user space

            for_each_possible_cpu(cpu) {
                struct throttler_stats *st = &per_cpu(local_stats, cpu); // puntatore alle statistiche dell'iesima CPU
                global_total_samples += st->total_blocked_samples;
                global_count += st->sample_count;
            }

            avg_data.tot = global_total_samples;
            avg_data.cnt = global_count;
            
            if (copy_to_user((void __user *)arg, &avg_data, sizeof(struct throttler_avg_data))) return -EFAULT;
            return 0;
        }

        case THROTTLER_IOC_GET_BLOCKED_THREAD:
            value = atomic_read(&blocked_threads_count); 
            if (copy_to_user((int __user *)arg, &value, sizeof(int))) return -EFAULT;
            return 0;

        case THROTTLER_IOC_GET_NUM_UIDS:
            count = num_target_uids;
            if (copy_to_user((int __user *)arg, &count, sizeof(int))) return -EFAULT;
            return 0;

        case THROTTLER_IOC_GET_UIDS:{
            int local_num_uids = num_target_uids;
            if (local_num_uids == 0) return 0;
            if (local_num_uids < 0) {
              pr_err("%s-DEV: num_target_uids is negative (%d)\n", MODNAME, local_num_uids);
              return -EFAULT;
            }
            k_uids = kmalloc_array(local_num_uids, sizeof(uid_t), GFP_KERNEL); // Alloca per contenere tutti gli UID
            if (!k_uids) return -ENOMEM;
            count = throttler_get_uids(k_uids, local_num_uids);
            if (count >= 0) {
                rc = copy_to_user((void __user *)arg, k_uids, sizeof(uid_t) * count) ? -EFAULT : 0;
            } else {
                rc = -EFAULT;
            }
            kfree(k_uids);
            return rc;
            }

        case THROTTLER_IOC_GET_NUM_PROGS:
            count = num_target_progs;
            if (copy_to_user((int __user *)arg, &count, sizeof(int))) return -EFAULT;
            return 0;

        case THROTTLER_IOC_GET_PROGS:{
            int local_num_progs = num_target_progs;
            if (local_num_progs == 0) return 0;
            if (local_num_progs < 0) {
              pr_err("%s-DEV: num_target_progs is negative (%d)\n", MODNAME, local_num_progs);
              return -EFAULT;
            }
            k_progs = kmalloc_array(local_num_progs, TASK_COMM_LEN, GFP_KERNEL); // Alloca per contenere tutti i programmi
            if (!k_progs) return -ENOMEM;
            
            count = throttler_get_progs(k_progs, local_num_progs);
            if (count >= 0) {
                rc = copy_to_user((void __user *)arg, k_progs, TASK_COMM_LEN * count) ? -EFAULT : 0;
            } else {
                rc = -EFAULT;
            }
            kfree(k_progs);
            return rc;
            }

        case THROTTLER_IOC_GET_NUM_SYSCALLS:
            count = bitmap_weight(monitored_syscalls, NR_syscalls);
            if (copy_to_user((int __user *)arg, &count, sizeof(int))) return -EFAULT;
            return 0;
        
        case THROTTLER_IOC_GET_SYSCALLS: 
            k_sys = kmalloc_array(NR_syscalls, sizeof(int), GFP_KERNEL);
            if (!k_sys) return -ENOMEM;

            count = throttler_get_syscalls(k_sys, NR_syscalls);

            if (count >= 0) {
                rc = copy_to_user((int __user *)arg, k_sys, sizeof(int) * count) ? -EFAULT : 0;
            } else {
                rc = count; 
            }

            kfree(k_sys);
            return rc;

        default:
            return -ENOTTY;
    }
}

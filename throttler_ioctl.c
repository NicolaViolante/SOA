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
    int i;
    int value;
    int rc;
    char prog_name[TASK_COMM_LEN];
    int *k_sys;
    int count;
    bool is_read_cmd = false;

    uid_t *k_uids;
    char (*k_progs)[TASK_COMM_LEN];
    
    //controllo se comando leggerà solamente o andrà a modificare il comportamento del modulo
    if (cmd == THROTTLER_IOC_GET_PEAK_DELAY || 
        cmd == THROTTLER_IOC_GET_PEAK_DELAY_INFO || 
        cmd == THROTTLER_IOC_GET_PEAK_BLOCKED || 
        cmd == THROTTLER_IOC_GET_AVG_BLOCKED || 
        cmd == THROTTLER_IOC_GET_BLOCKED_THREAD || 
        cmd == THROTTLER_IOC_GET_NUM_UIDS || 
        cmd == THROTTLER_IOC_GET_UIDS || 
        cmd == THROTTLER_IOC_GET_NUM_PROGS || 
        cmd == THROTTLER_IOC_GET_PROGS || 
        cmd == THROTTLER_IOC_GET_NUM_SYSCALLS || 
        cmd == THROTTLER_IOC_GET_SYSCALLS) {
        
        is_read_cmd = true;
    }
    
    if (!is_read_cmd && current_euid().val != 0) { // se non è un comando di letture e non si è root warning
        printk(KERN_WARNING "THROTTLER-DEV: Access denied (EUID %u). Only root can modify monitor.\n", current_euid().val);
        return -EPERM;
    }

    switch (cmd) {
        case THROTTLER_IOC_MONITOR_ON:
            atomic_set(&monitor_on, 1); //imposta atomicamente valore monitor ad 1 per accenderlo
            printk(KERN_INFO "THROTTLER-DEV: Monitor activated\n");
            return 0;

        case THROTTLER_IOC_MONITOR_OFF:
            atomic_set(&monitor_on, 0); //imposta atomicamente valore monitor ad 0 per spegnerlo
            printk(KERN_INFO "THROTTLER-DEV: Monitor deactivated\n");
            wake_up_all(&throttle_wq); // allo spegnimento bisogna svuotare la waitqueue
            throttler_reset_stats(); // azzeramento statistiche per prossima accensione
            return 0;

        case THROTTLER_IOC_SET_MAX:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT; //bad address in caso di fallimento
            if (value <= 0) return -EINVAL;
            max_syscalls_per_sec = value; // imposta valore passato da user space
            printk(KERN_INFO "THROTTLER-DEV: Max syscalls/sec: %d\n", value);
            return 0;

        case THROTTLER_IOC_ADD_SYSCALL:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            if (value < 0 || value >= NR_syscalls) {
              pr_err("THROTTLER: Invalid syscall number %d\n", value);
              return -EINVAL;
              }
            printk(KERN_INFO "THROTTLER-DEV: Syscall number %d will be monitored\n", value);
            return hook_syscall(value); //chiama funzione che altera la system call table alla entry specificata

        case THROTTLER_IOC_REMOVE_SYSCALL:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            if (value < 0 || value >= NR_syscalls) {
              pr_err("THROTTLER-DEV: Invalid syscall number %d\n", value);
              return -EINVAL;
            }
            printk(KERN_INFO "THROTTLER-DEV: Syscall number %d will not be monitored anymore\n", value);
            return throttler_unhook_syscall(value); //chiama funzione che ripristina la system call table alla entry specificata

        case THROTTLER_IOC_ADD_UID:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            printk(KERN_INFO "THROTTLER-DEV: User ID %d will be monitored\n", value);
            return throttler_add_uid((uid_t)value); // aggiunge valore alla lista RCU

        case THROTTLER_IOC_REMOVE_UID:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            printk(KERN_INFO "THROTTLER-DEV: User ID %d will not be monitored anymore\n", value);
            return throttler_remove_uid((uid_t)value); // rimuove valore dalla lista RCU

        case THROTTLER_IOC_ADD_PROG:
            if (copy_from_user(prog_name, (char __user *)arg, TASK_COMM_LEN)) return -EFAULT;
            prog_name[TASK_COMM_LEN-1] = '\0';
            if (strlen(prog_name) == 0) return -EINVAL;
            printk(KERN_INFO "THROTTLER-DEV: Program %s will be monitored\n", prog_name);
            return throttler_add_prog(prog_name);

        case THROTTLER_IOC_REMOVE_PROG:
            if (copy_from_user(prog_name, (char __user *)arg, TASK_COMM_LEN)) return -EFAULT;
            prog_name[TASK_COMM_LEN-1] = '\0';
            if (strlen(prog_name) == 0) return -EINVAL;
            printk(KERN_INFO "THROTTLER-DEV: Program %s will not be monitored anymore\n", prog_name);
            return throttler_remove_prog(prog_name);

        case THROTTLER_IOC_GET_PEAK_DELAY:
        case THROTTLER_IOC_GET_PEAK_DELAY_INFO:
        case THROTTLER_IOC_GET_PEAK_BLOCKED: {
            int cpu;
            unsigned long global_peak_ns = 0;
            int global_peak_blocked = 0;
            char global_peak_info[64] = ""; // stringa per specificare nome e UID che ha generato il picco
            
            for_each_possible_cpu(cpu) {
                struct throttler_stats *st = &per_cpu(local_stats, cpu); // puntatore alle statistiche dell'iesima CPU
                
                if (st->peak_delay_ns > global_peak_ns) { // controllo se picco di ritardo registrato dalla specifica CPU è il più grande 
                    global_peak_ns = st->peak_delay_ns;
                    snprintf(global_peak_info, sizeof(global_peak_info), "Prog: %s, UID: %u", st->peak_delay_prog, st->peak_delay_uid);
                    }
                if (st->peak_blocked_threads > global_peak_blocked) { // controllo se picco di thread bloccati registrato dalla specifica CPU è il più grande 
                    global_peak_blocked = st->peak_blocked_threads;
                }
            }

            if (cmd == THROTTLER_IOC_GET_PEAK_DELAY) {
                if (copy_to_user((unsigned long __user *)arg, &global_peak_ns, sizeof(unsigned long))) return -EFAULT;
            } else if (cmd == THROTTLER_IOC_GET_PEAK_DELAY_INFO) {
                if (copy_to_user((char __user *)arg, global_peak_info, sizeof(global_peak_info))) return -EFAULT;
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

        case THROTTLER_IOC_GET_UIDS:
            if (num_target_uids == 0) return 0;
            if (num_target_uids < 0) {
              pr_err("THROTTLER-DEV: num_target_uids is negative (%d)\n", num_target_uids);
              return -EFAULT;
            }
            k_uids = kmalloc_array(num_target_uids, sizeof(uid_t), GFP_KERNEL); // Alloca per contenere tutti gli UID
            if (!k_uids) return -ENOMEM;
            count = throttler_get_uids(k_uids, num_target_uids);
            if (count >= 0) {
                rc = copy_to_user((void __user *)arg, k_uids, sizeof(uid_t) * count) ? -EFAULT : 0;
            } else {
                rc = -EFAULT;
            }
            kfree(k_uids);
            return rc;

        case THROTTLER_IOC_GET_NUM_PROGS:
            count = num_target_progs;
            if (copy_to_user((int __user *)arg, &count, sizeof(int))) return -EFAULT;
            return 0;

        case THROTTLER_IOC_GET_PROGS:
            if (num_target_progs == 0) return 0;
            if (num_target_progs < 0) {
              pr_err("THROTTLER-DEV: num_target_progs is negative (%d)\n", num_target_progs);
              return -EFAULT;
            }
            k_progs = kmalloc_array(num_target_progs, TASK_COMM_LEN, GFP_KERNEL); // Alloca per contenere tutti i programmi
            if (!k_progs) return -ENOMEM;
            
            count = throttler_get_progs(k_progs, num_target_progs);
            if (count >= 0) {
                rc = copy_to_user((void __user *)arg, k_progs, TASK_COMM_LEN * count) ? -EFAULT : 0;
            } else {
                rc = -EFAULT;
            }
            kfree(k_progs);
            return rc;

        case THROTTLER_IOC_GET_NUM_SYSCALLS:
            count = 0;
            for (i = 0; i < NR_syscalls; i++) {
                if (monitored_syscalls[i]) {
                    count++;
                }
            }
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

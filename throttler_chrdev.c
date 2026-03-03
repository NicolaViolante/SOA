#include <linux/module.h>
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/slab.h> 
#include <linux/percpu.h>
#include <linux/cpumask.h> 

#include "throttler_chrdev.h"
#include "throttler_ioctl.h"
#include "throttler_internal.h"

#define DEVICE_NAME  "syscall_throttler"
#define DEVICE_CLASS "throttler_class"

struct throttler_cdev {
    dev_t        dev;
    struct cdev  cdev;
    struct class *class;
};

static struct throttler_cdev device;

static long throttler_ioctl_dispatcher(struct file *file, unsigned int cmd, unsigned long arg) {
    int value;
    int rc;
    char prog_name[TASK_COMM_LEN];
    int *k_sys;
    int count;
    bool is_read_cmd = false;

    uid_t *k_uids;
    char (*k_progs)[TASK_COMM_LEN];

    if (cmd == THROTTLER_IOC_GET_PEAK_DELAY || 
        cmd == THROTTLER_IOC_GET_PEAK_DELAY_INFO || 
        cmd == THROTTLER_IOC_GET_PEAK_BLOCKED || 
        cmd == THROTTLER_IOC_GET_AVG_BLOCKED || 
        cmd == THROTTLER_IOC_GET_BLOCKED_THREAD || 
        cmd == THROTTLER_IOC_GET_NUM_UIDS || 
        cmd == THROTTLER_IOC_GET_UIDS || 
        cmd == THROTTLER_IOC_GET_NUM_PROGS || 
        cmd == THROTTLER_IOC_GET_PROGS || 
        cmd == THROTTLER_IOC_GET_SYSCALLS) {
        
        is_read_cmd = true;
    }

    if (!is_read_cmd && current_euid().val != 0) {
        printk(KERN_WARNING "THROTTLER-DEV: Access denied (EUID %u). Only root can modify monitor.\n", current_euid().val);
        return -EPERM;
    }

    switch (cmd) {
        case THROTTLER_IOC_MONITOR_ON:
            atomic_set(&monitor_on, 1); 
            printk(KERN_INFO "THROTTLER-DEV: Monitor activated\n");
            return 0;

        case THROTTLER_IOC_MONITOR_OFF:
            atomic_set(&monitor_on, 0); 
            printk(KERN_INFO "THROTTLER-DEV: Monitor deactivated\n");
            wake_up_all(&throttle_wq); 
            throttler_reset_stats();
            return 0;

        case THROTTLER_IOC_SET_MAX:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            if (value <= 0) return -EINVAL;
            max_syscalls_per_sec = value;
            printk(KERN_INFO "THROTTLER-DEV: Max syscalls/sec: %d\n", value);
            return 0;

        case THROTTLER_IOC_ADD_SYSCALL:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            if (value < 0 || value >= NR_syscalls) return -EINVAL;
            printk(KERN_INFO "THROTTLER-DEV: Syscall number %d will be monitored\n", value);
            hook_syscall(value);
            return 0;

        case THROTTLER_IOC_REMOVE_SYSCALL:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            if (value < 0 || value >= NR_syscalls) return -EINVAL;
            printk(KERN_INFO "THROTTLER-DEV: Syscall number %d will not be monitored anymore\n", value);
            rc = throttler_unhook_syscall(value);
            return rc;

        case THROTTLER_IOC_ADD_UID:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            printk(KERN_INFO "THROTTLER-DEV: User ID %d will be monitored\n", value);
            rc = throttler_add_uid((uid_t)value);
            return rc;

        case THROTTLER_IOC_REMOVE_UID:
            if (copy_from_user(&value, (int __user *)arg, sizeof(int))) return -EFAULT;
            printk(KERN_INFO "THROTTLER-DEV: User ID %d will not be monitored anymore\n", value);
            rc = throttler_remove_uid((uid_t)value);
            return rc;

        case THROTTLER_IOC_ADD_PROG:
            if (copy_from_user(prog_name, (char __user *)arg, TASK_COMM_LEN)) return -EFAULT;
            prog_name[TASK_COMM_LEN-1] = '\0';
            printk(KERN_INFO "THROTTLER-DEV: Program %s will be monitored\n", prog_name);
            rc = throttler_add_prog(prog_name);
            return rc;

        case THROTTLER_IOC_REMOVE_PROG:
            if (copy_from_user(prog_name, (char __user *)arg, TASK_COMM_LEN)) return -EFAULT;
            prog_name[TASK_COMM_LEN-1] = '\0';
            printk(KERN_INFO "THROTTLER-DEV: Program %s will not be monitored anymore\n", prog_name);
            rc = throttler_remove_prog(prog_name);
            return rc;

        case THROTTLER_IOC_GET_PEAK_DELAY:
        case THROTTLER_IOC_GET_PEAK_DELAY_INFO:
        case THROTTLER_IOC_GET_PEAK_BLOCKED: {
            int cpu;
            unsigned long global_peak_ns = 0;
            int global_peak_blocked = 0;
            char global_peak_info[64] = "";
            
            for_each_possible_cpu(cpu) {
                struct throttler_stats *st = &per_cpu(local_stats, cpu);
                
                if (st->peak_delay_ns > global_peak_ns) {
                    global_peak_ns = st->peak_delay_ns;
                    snprintf(global_peak_info, sizeof(global_peak_info), 
                             "Prog: %s, UID: %u", st->peak_delay_prog, st->peak_delay_uid);
                }
                if (st->peak_blocked_threads > global_peak_blocked) {
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
            unsigned long global_total_samples = 0;
            unsigned long global_count = 0;
            struct { unsigned long tot; 
                     unsigned long cnt; } avg_data;

            for_each_possible_cpu(cpu) {
                struct throttler_stats *st = &per_cpu(local_stats, cpu);
                global_total_samples += st->total_blocked_samples;
                global_count += st->sample_count;
            }

            avg_data.tot = global_total_samples;
            avg_data.cnt = global_count;
            
            if (copy_to_user((void __user *)arg, &avg_data, sizeof(avg_data))) return -EFAULT;
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
            if (num_target_uids <= 0) return 0;
            k_uids = kmalloc_array(num_target_uids, sizeof(uid_t), GFP_KERNEL);
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
            if (num_target_progs <= 0) return 0;
            k_progs = kmalloc_array(num_target_progs, TASK_COMM_LEN, GFP_KERNEL);
            if (!k_progs) return -ENOMEM;
            
            count = throttler_get_progs(k_progs, num_target_progs);
            if (count >= 0) {
                rc = copy_to_user((void __user *)arg, k_progs, TASK_COMM_LEN * count) ? -EFAULT : 0;
            } else {
                rc = -EFAULT;
            }
            kfree(k_progs);
            return rc;

        case THROTTLER_IOC_GET_SYSCALLS:
            k_sys = kmalloc_array(NR_syscalls, sizeof(int), GFP_KERNEL);
            if (!k_sys) return -ENOMEM;

            count = throttler_get_syscalls(k_sys, NR_syscalls);

            if (count >= 0) {
                rc = copy_to_user((int __user *)arg, k_sys, sizeof(int) * count) ? -EFAULT : count;
            } else {
                rc = count; 
            }

            kfree(k_sys);
            return rc;

        default:
            return -ENOTTY;
    }
}

static const struct file_operations ops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = throttler_ioctl_dispatcher
};

static int throttler_uevent(const struct device *dev, struct kobj_uevent_env *env) {
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

int throttler_chrdev_init(void) {
    int err = alloc_chrdev_region(&device.dev, 0, 1, DEVICE_NAME);
    if (err) {
      pr_err("Cannot register char device %s, got error %d\n", DEVICE_NAME, err);
      return err;
    }
    
    cdev_init(&device.cdev, &ops);
    device.cdev.owner = THIS_MODULE;
    err = cdev_add(&device.cdev, device.dev, 1);
    if (err) {
      pr_err("Cannot add device %d:%d, got error %d\n", MAJOR(device.dev),MINOR(device.dev),err);
      goto out;
    }

    struct class *device_class = class_create(DEVICE_CLASS);

    if (IS_ERR(device_class)) {
        err = PTR_ERR(device_class);
        pr_err("Cannot create class %s, got error %d\n", DEVICE_CLASS, err);
        goto out2;
    }
    
    device_class->dev_uevent = throttler_uevent;
    device.class = device_class;
    
    struct device *dp = device_create(device.class, NULL, device.dev, NULL, DEVICE_NAME);
    if (IS_ERR(dp)) {
        err = PTR_ERR(dp);
        pr_err("Cannot create device /dev/%s, got error %d\n", DEVICE_NAME, err);
        goto out3;
    }
    
    pr_info("Device /dev/%s inizializzato con successo!\n", DEVICE_NAME);
    return 0;

out3: 
    class_destroy(device.class);
    device.class = NULL;
out2: 
    cdev_del(&device.cdev);
out:  
    unregister_chrdev_region(device.dev, 1);
    device.dev = 0;
    return err;
}

void throttler_chrdev_cleanup(void) {
    device_destroy(device.class, device.dev);
    class_destroy(device.class);
    device.class = NULL;
    cdev_del(&device.cdev);
    unregister_chrdev_region(device.dev, 1);
    device.dev = 0;
}

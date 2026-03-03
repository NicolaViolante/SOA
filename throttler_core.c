#include <linux/module.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/percpu.h>
#include "throttler_internal.h"

atomic_t monitor_on = ATOMIC_INIT(0);
int max_syscalls_per_sec = 10;

DEFINE_PER_CPU(struct throttler_stats, local_stats);

atomic_t blocked_threads_count = ATOMIC_INIT(0);
DECLARE_WAIT_QUEUE_HEAD(throttle_wq);
static struct timer_list wakeup_timer;
atomic_t timer_active = ATOMIC_INIT(0);

atomic_t available_tokens = ATOMIC_INIT(0);
atomic64_t last_second = ATOMIC64_INIT(0);

static int try_grab_token_wait(void) {
    return atomic_add_unless(&available_tokens, -1, 0);
}

static void wakeup_timer_func(struct timer_list *t) {
    long now_sec = (long)ktime_get_real_seconds();
    long old_sec = atomic64_read(&last_second);

    if (old_sec != now_sec) {
        if (atomic64_cmpxchg(&last_second, old_sec, now_sec) == old_sec) {
            atomic_set(&available_tokens, max_syscalls_per_sec);
        }
    }

    wake_up_all(&throttle_wq);
    if (atomic_read(&blocked_threads_count) > 0 && atomic_read(&monitor_on)) {
        unsigned long ns_remainder = ktime_get_real_ns() % 1000000000;
        unsigned long ms_to_next_sec = 1000 - (ns_remainder / 1000000);
        mod_timer(t, jiffies + msecs_to_jiffies(ms_to_next_sec));
    } else {
        atomic_set(&timer_active, 0);
    }
}

long universal_syscall_wrapper(const struct pt_regs *regs) {
    int sys_nr = regs->orig_ax;
    int got_token = 0;
    
    if (atomic_read(&monitor_on) && sys_nr >= 0 && sys_nr < NR_syscalls && monitored_syscalls[sys_nr]) {
        int task_matched = 0;
        struct target_uid_node *uid_node;
        struct target_prog_node *prog_node;
        
        rcu_read_lock();
        
        list_for_each_entry_rcu(uid_node, &target_uids_list, list) {
            if (current_euid().val == uid_node->uid) {
                task_matched = 1; 
                break;
            }
        }
        
        if (!task_matched) {
            list_for_each_entry_rcu(prog_node, &target_progs_list, list) {
                if (strncmp(current->comm, prog_node->prog, TASK_COMM_LEN) == 0) {
                    task_matched = 1; 
                    break;
                }
            }
        }
        
        rcu_read_unlock();

        if (task_matched) {
            long now_sec = (long)ktime_get_real_seconds();
            long old_sec = atomic64_read(&last_second);
            
            if (old_sec != now_sec) {
                if (atomic64_cmpxchg(&last_second, old_sec, now_sec) == old_sec) {
                    atomic_set(&available_tokens, max_syscalls_per_sec);
                    wake_up_all(&throttle_wq);
                }
            }
            
            got_token = atomic_add_unless(&available_tokens, -1, 0);

            if (!got_token) {
                ktime_t start_time = ktime_get();
                ktime_t end_time;
                unsigned long diff_ns;
                int current_blocked = atomic_inc_return(&blocked_threads_count);
                struct throttler_stats *st;
                int wait_res;

                st = &get_cpu_var(local_stats);
                if (current_blocked > st->peak_blocked_threads) 
                    st->peak_blocked_threads = current_blocked;
                st->total_blocked_samples += current_blocked;
                st->sample_count++;
                put_cpu_var(local_stats);

                if (atomic_cmpxchg(&timer_active, 0, 1) == 0) {
                    unsigned long ns_remainder = ktime_get_real_ns() % 1000000000;
                    unsigned long ms_to_next_sec = 1000 - (ns_remainder / 1000000);
                    mod_timer(&wakeup_timer, jiffies + msecs_to_jiffies(ms_to_next_sec));
                }

                wait_res = wait_event_interruptible(throttle_wq, !atomic_read(&monitor_on) || try_grab_token_wait());

                atomic_dec(&blocked_threads_count);
                end_time = ktime_get();
                diff_ns = ktime_to_ns(end_time) - ktime_to_ns(start_time);

                st = &get_cpu_var(local_stats);
                if (diff_ns > st->peak_delay_ns) {
                    st->peak_delay_ns = diff_ns;
                    st->peak_delay_uid = current_euid().val;
                    strscpy(st->peak_delay_prog, current->comm, TASK_COMM_LEN);
                }
                put_cpu_var(local_stats);

                if (wait_res != 0) {
                    return -ERESTARTSYS;
                }
            }
        }
    }

    if (sys_nr >= 0 && sys_nr < NR_syscalls && original_sys_funcs[sys_nr])
        return original_sys_funcs[sys_nr](regs);

    return -ENOSYS;
}

void throttler_reset_stats(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        struct throttler_stats *st = &per_cpu(local_stats, cpu);
        memset(st, 0, sizeof(struct throttler_stats));
    }
    atomic_set(&blocked_threads_count, 0);
}

void throttler_core_init(void) {
    timer_setup(&wakeup_timer, wakeup_timer_func, 0);
}

void throttler_core_cleanup(void) {
    unhook_all_syscalls();
    timer_delete_sync(&wakeup_timer);
    atomic_set(&monitor_on, 0);
    wake_up_all(&throttle_wq);
    while (atomic_read(&blocked_threads_count) > 0) {
        msleep(10); 
    }
}

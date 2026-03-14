#include <linux/module.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/percpu.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include "throttler_internal.h"

atomic_t monitor_on = ATOMIC_INIT(0);
int max_syscalls_per_sec = 10;
DEFINE_PER_CPU(struct throttler_stats, local_stats);
atomic_t blocked_threads_count = ATOMIC_INIT(0);
DEFINE_PER_CPU(int, threads_in_wrapper);
DECLARE_WAIT_QUEUE_HEAD(throttle_wq);
static struct timer_list wakeup_timer;
atomic_t timer_active = ATOMIC_INIT(0);
atomic_t available_tokens = ATOMIC_INIT(0);
atomic64_t last_second = ATOMIC64_INIT(0);

static int try_grab_token_wait(void) {
    return atomic_add_unless(&available_tokens, -1, 0); //sottrae solamente se #gettoni > 0
}

static void wakeup_timer_func(struct timer_list *t) { //funzione di callback del timer
    long now_sec = (long)ktime_get_seconds();
    long old_sec = atomic64_read(&last_second);
    if (old_sec != now_sec) {
        if (atomic64_cmpxchg(&last_second, old_sec, now_sec) == old_sec) { //controllo sul tempo per verificare se i gettoni sono stati già ricaricati
            atomic_set(&available_tokens, max_syscalls_per_sec);
        }
    }
    wake_up_all(&throttle_wq);
    if (atomic_read(&blocked_threads_count) > 0 && atomic_read(&monitor_on)) {
        unsigned long ns_remainder = ktime_get_ns() % 1000000000; // calcolo dei nanosecondi trascorsi nel secondo corrente
        unsigned long ms_to_next_sec = 1000 - (ns_remainder / 1000000); // calcolo dei millisecondi rimanenti per il secondo successivo
        mod_timer(t, jiffies + msecs_to_jiffies(ms_to_next_sec)); // setup timer interrupt
    } else {
        atomic_set(&timer_active, 0); //spegnimento del timer
    }
}

long universal_syscall_wrapper(const struct pt_regs *regs) {
    int sys_nr = regs->orig_ax; //estrazione numero system call
    int got_token = 0;
    long ret;
    this_cpu_inc(threads_in_wrapper);
    
    if (atomic_read(&monitor_on) && sys_nr >= 0 && sys_nr < NR_syscalls && test_bit(sys_nr, monitored_syscalls)) { //controlli su accensione monitor e numero system call
        int task_matched = 0;
        struct target_uid_node *uid_node;
        struct target_prog_node *prog_node;
        
        rcu_read_lock(); //acquisizione lock RCU
        
        uid_t current_uid = current_euid().val;
        
        hash_for_each_possible_rcu(target_uids_hash, uid_node, hnode, current_uid) {
            if (current_uid == uid_node->uid) {
                task_matched = 1; 
                break;
            }
        }
        
        if (!task_matched) {
            u32 hash = jhash(current->comm, strnlen(current->comm, TASK_COMM_LEN), 0);
            hash_for_each_possible_rcu(target_progs_hash, prog_node, hnode, hash) {
                if (strncmp(current->comm, prog_node->prog, TASK_COMM_LEN) == 0) {
                    task_matched = 1; 
                    break;
                }
            }
        }
        
        rcu_read_unlock(); //fine delle letture delle liste

        if (task_matched) {
            long now_sec = (long)ktime_get_seconds();
            long old_sec = atomic64_read(&last_second);
            
            if (old_sec != now_sec) {
                if (atomic64_cmpxchg(&last_second, old_sec, now_sec) == old_sec) { //ricarica dei gettoni senza utilizzo del timer
                    atomic_set(&available_tokens, max_syscalls_per_sec);
                    wake_up_all(&throttle_wq);
                }
            }
            
            got_token = atomic_add_unless(&available_tokens, -1, 0); //tentativo di acquisizione gettone in maniera Lock-free

            if (!got_token) {
                unsigned long start_time = ktime_get_ns(); //utilizzo di un clock monotonic per precisione nelle statistiche
                                                     // /sys/devices/system/clocksource/clocksource0/current_clocksource (nel mio sistema usato tsc)
                unsigned long end_time;
                unsigned long diff_ns;
                int current_blocked = atomic_inc_return(&blocked_threads_count); //aumento del numero di thread bloccati nel sistema di un unità
                struct throttler_stats *st;
                int wait_res;

                st = &get_cpu_var(local_stats); //disabilitazione preemption e aggiornamento delle statistiche per CPU
                if (current_blocked > st->peak_blocked_threads) 
                    st->peak_blocked_threads = current_blocked;
                st->total_blocked_samples += current_blocked;
                st->sample_count++;
                put_cpu_var(local_stats);

                if (atomic_cmpxchg(&timer_active, 0, 1) == 0) { // attivazione del timer per ricaricare i gettoni ed evitare situazioni nelle quali i gettoni non vengono mai ricaricati
                    unsigned long ns_remainder = ktime_get_ns() % 1000000000;
                    unsigned long ms_to_next_sec = 1000 - (ns_remainder / 1000000);
                    mod_timer(&wakeup_timer, jiffies + msecs_to_jiffies(ms_to_next_sec));
                }

                wait_res = wait_event_interruptible(throttle_wq, !atomic_read(&monitor_on) || try_grab_token_wait()); //thread messo in wait-queue, in caso risvegliato da segnale valore diverso da zero

                atomic_dec(&blocked_threads_count);
                end_time = ktime_get_ns();
                diff_ns = end_time - start_time;

                st = &get_cpu_var(local_stats); //disabilitazione preemption e aggiornamento delle statistiche per CPU
                if (diff_ns > st->peak_delay_ns) {
                    st->peak_delay_ns = diff_ns;
                    st->peak_delay_uid = current_euid().val;
                    strscpy(st->peak_delay_prog, current->comm, TASK_COMM_LEN);
                }
                put_cpu_var(local_stats);

                if (wait_res != 0) {
                    this_cpu_dec(threads_in_wrapper);
                    return -ERESTARTSYS;
                }
            }
        }
    }

    if (sys_nr >= 0 && sys_nr < NR_syscalls && original_sys_funcs[sys_nr]) {
        ret = original_sys_funcs[sys_nr](regs);
    } else {
        ret = -ENOSYS;
    }
    this_cpu_dec(threads_in_wrapper);
    return ret;
}

void throttler_reset_stats(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        struct throttler_stats *st = &per_cpu(local_stats, cpu);
        memset(st, 0, sizeof(struct throttler_stats)); //azzera la memoria dell'intera struttura
    }
}

void throttler_core_init(void) {
    timer_setup(&wakeup_timer, wakeup_timer_func, 0); //associazione timer a funzione di callback
}

void throttler_core_cleanup(void) {
    int cpu;
    int sum;
    
    unhook_all_syscalls(); // traffico non passa più attraverso il monitor, la system call table originale viene ripristinata
    timer_delete_sync(&wakeup_timer); //eliminazione timer in modo sincrono
    atomic_set(&monitor_on, 0); // spegnimento monitor
    wake_up_all(&throttle_wq); // risveglio di tutti  i threads
    
    pr_info("%s: Waiting for threads to exit the wrapper before unloading...\n", MODNAME);
    do {
        sum = 0;
        
        for_each_possible_cpu(cpu) {
            sum += per_cpu(threads_in_wrapper, cpu);
        }
        
        if (sum > 0) {
            msleep(10); 
        }
    } while (sum > 0);

    msleep(50); 
    pr_info("%s: All threads exited. Safe to unload.\n", MODNAME);
}


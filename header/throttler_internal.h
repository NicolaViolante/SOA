#ifndef THROTTLER_INTERNAL_H
#define THROTTLER_INTERNAL_H

#include <linux/types.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/hashtable.h>
#include <linux/bitmap.h>

#define MODNAME "THROTTLER"
#define PROG_HASH_BITS 8
#define UID_HASH_BITS 8

extern atomic_t monitor_on;
extern int max_syscalls_per_sec;
extern DECLARE_BITMAP(monitored_syscalls, NR_syscalls);

struct throttler_stats {
    unsigned long peak_delay_ns;
    uid_t peak_delay_uid;
    char peak_delay_prog[TASK_COMM_LEN];
    int peak_blocked_threads;
    unsigned long total_blocked_samples;
    unsigned long sample_count;
};

DECLARE_PER_CPU(struct throttler_stats, local_stats);

extern atomic_t blocked_threads_count;
DECLARE_PER_CPU(int, threads_in_wrapper);
extern wait_queue_head_t throttle_wq;
extern spinlock_t config_lock; 

struct target_uid_node {
    uid_t uid;
    struct hlist_node hnode;
    struct rcu_head rcu;
};

struct target_prog_node {
    char prog[TASK_COMM_LEN];
    struct hlist_node hnode;
    struct rcu_head rcu;
};

extern DECLARE_HASHTABLE(target_uids_hash, UID_HASH_BITS);
extern int num_target_uids;
extern DECLARE_HASHTABLE(target_progs_hash, PROG_HASH_BITS); 
extern int num_target_progs;

extern unsigned long **hacked_syscall_tbl;
int throttler_memory_init(void);
void throttler_memory_cleanup(void);
void begin_syscall_table_hack(unsigned long *cr0, unsigned long *cr4);
void end_syscall_table_hack(unsigned long cr0, unsigned long cr4);
long universal_syscall_wrapper(const struct pt_regs *regs);

extern long (*original_sys_funcs[NR_syscalls])(const struct pt_regs *);
int hook_syscall(int nr);
int throttler_unhook_syscall(int nr);
int unhook_all_syscalls(void);
void throttler_core_init(void);
void throttler_core_cleanup(void);
void throttler_reset_stats(void);

int throttler_add_uid(uid_t uid);
int throttler_remove_uid(uid_t uid);
int throttler_add_prog(const char *prog);
int throttler_remove_prog(const char *prog);
int throttler_get_uids(uid_t *buf, int max);
int throttler_get_progs(char (*buf)[TASK_COMM_LEN], int max);
int throttler_get_syscalls(int *buf, int max);
void throttler_config_cleanup(void);

int throttler_chrdev_init(void);
void throttler_chrdev_cleanup(void);

long throttler_ioctl_dispatcher(struct file *file, unsigned int cmd, unsigned long arg);
#endif 

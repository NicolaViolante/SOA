#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/hashtable.h> 
#include <linux/jhash.h>
#include "throttler_internal.h"

DEFINE_SPINLOCK(config_lock);

DEFINE_HASHTABLE(target_uids_hash, UID_HASH_BITS); //inizializzazione hash table
int num_target_uids = 0; // contatore su uid attualmente in lista

DEFINE_HASHTABLE(target_progs_hash, PROG_HASH_BITS); // inizializzazione hash table
int num_target_progs = 0; // contatore su programmi attualmente in lista

int throttler_add_uid(uid_t uid) {
    struct target_uid_node *new_node; // nuovo nodo da allocare
    struct target_uid_node *curr;
    unsigned long flags; // per salvare stato interrupt

    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) {
        return -ENOMEM;
    }
    new_node->uid = uid;
    spin_lock_irqsave(&config_lock, flags);
    hash_for_each_possible(target_uids_hash, curr, hnode, uid) {
        if (curr->uid == uid) { 
            spin_unlock_irqrestore(&config_lock, flags);
            kfree(new_node); 
            return 0; // Già presente
        }
    }
    hash_add_rcu(target_uids_hash, &new_node->hnode, uid);
    num_target_uids++;
    spin_unlock_irqrestore(&config_lock, flags);
    
    return 0;
}

int throttler_remove_uid(uid_t uid) {
    struct target_uid_node *curr;
    unsigned long flags; // stato interrupt
    bool found = false;

    spin_lock_irqsave(&config_lock, flags);

    hash_for_each_possible(target_uids_hash, curr, hnode, uid) {
        if (curr->uid == uid) {
            hash_del_rcu(&curr->hnode); // Rimuove il nodo
            num_target_uids--;
            found = true;
            break;
        }
    }
    
    spin_unlock_irqrestore(&config_lock, flags);

    if (found) {
        kfree_rcu(curr, rcu);
        return 0;
    }
    return -ENOENT;
}

int throttler_add_prog(const char *prog) {
    struct target_prog_node *new_node;
    struct target_prog_node *curr;
    unsigned long flags;
    u32 hash;

    if (!prog) return -EINVAL;
    
    hash = jhash(prog, strnlen(prog, TASK_COMM_LEN), 0);
    
    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) {
        return -ENOMEM;
    }
    strscpy(new_node->prog, prog, TASK_COMM_LEN);//copia sicura della stringa, massimo 16 caratteri
    spin_lock_irqsave(&config_lock, flags);
    
    hash_for_each_possible(target_progs_hash, curr, hnode, hash) {
        if (strncmp(curr->prog, new_node->prog, TASK_COMM_LEN) == 0) {
            spin_unlock_irqrestore(&config_lock, flags);
            kfree(new_node); 
            return 0;
        }
    }
    hash_add_rcu(target_progs_hash, &new_node->hnode, hash);
    num_target_progs++;
    spin_unlock_irqrestore(&config_lock, flags);
    
    return 0;
}

int throttler_remove_prog(const char *prog) {
    struct target_prog_node *curr;
    unsigned long flags;
    bool found = false;
    u32 hash;

    if (!prog) return -EINVAL;
    
    hash = jhash(prog, strnlen(prog, TASK_COMM_LEN), 0);
    
    spin_lock_irqsave(&config_lock, flags);
    
    hash_for_each_possible(target_progs_hash, curr, hnode, hash) {
        if (strncmp(curr->prog, prog, TASK_COMM_LEN) == 0) { 
            hash_del_rcu(&curr->hnode); // Rimozione sicura per i reader RCU
            num_target_progs--;
            found = true;
            break;
        }
    }
    
    spin_unlock_irqrestore(&config_lock, flags);

    if (found) {
        kfree_rcu(curr, rcu); //la free della memoria avviene in modo deferred dopo grace period
        return 0;
    }
    return -ENOENT;
}

int throttler_get_uids(uid_t *buf, int max) {
    struct target_uid_node *curr;
    int bkt;
    int n = 0;

    if (!buf || max <= 0) return -EINVAL;
    
    rcu_read_lock();
    
    hash_for_each_rcu(target_uids_hash, bkt, curr, hnode) {
        if (n >= max) break;
        buf[n++] = curr->uid;
    }
    
    rcu_read_unlock();
    
    return n;
}

int throttler_get_progs(char (*buf)[TASK_COMM_LEN], int max) {
    struct target_prog_node *curr;
    int bkt;
    int n = 0;

    if (!buf || max <= 0) return -EINVAL;

    rcu_read_lock();
    hash_for_each_rcu(target_progs_hash, bkt, curr, hnode) {
        if (n >= max) break;
        strscpy(buf[n++], curr->prog, TASK_COMM_LEN);
    }
    rcu_read_unlock();
    
    return n;
}

void throttler_config_cleanup(void) {
    struct target_uid_node *uid_curr;
    struct hlist_node *uid_tmp;
    struct target_prog_node *prog_curr;
    struct hlist_node *prog_tmp;
    int bkt;

    hash_for_each_safe(target_uids_hash, bkt, uid_tmp, uid_curr, hnode) {
        hash_del_rcu(&uid_curr->hnode);
        kfree_rcu(uid_curr, rcu);
    }
    
    hash_for_each_safe(target_progs_hash, bkt, prog_tmp, prog_curr, hnode) {
        hash_del_rcu(&prog_curr->hnode);
        kfree_rcu(prog_curr, rcu);
    }
    rcu_barrier(); //serve poichè a causa delle kfree-rcu
}

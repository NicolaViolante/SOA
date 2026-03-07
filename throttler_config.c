#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include "throttler_internal.h"

DEFINE_SPINLOCK(config_lock);

LIST_HEAD(target_uids_list); // inizializzazione testa lista concatenata per uid
int num_target_uids = 0; // contatore su uid attualmente in lista

LIST_HEAD(target_progs_list); // inizializzazione testa lista concatenata per programmi
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
    list_for_each_entry(curr, &target_uids_list, list) {
        if (curr->uid == uid) { // controllo se uid già monitorato
            spin_unlock_irqrestore(&config_lock, flags);
            kfree(new_node); 
            return 0;
        }
    }
    list_add_rcu(&new_node->list, &target_uids_list);
    num_target_uids++;
    spin_unlock_irqrestore(&config_lock, flags);
    
    return 0;
}

int throttler_remove_uid(uid_t uid) {
    struct target_uid_node *curr;
    unsigned long flags; // stato interrupt
    bool found = false;

    spin_lock_irqsave(&config_lock, flags);

    list_for_each_entry(curr, &target_uids_list, list) {
        if (curr->uid == uid) {
            list_del_rcu(&curr->list); // rimozione nodo
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

    if (!prog) return -EINVAL;
    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) {
        return -ENOMEM;
    }
    strscpy(new_node->prog, prog, TASK_COMM_LEN);//copia sicura della stringa, massimo 16 caratteri
    spin_lock_irqsave(&config_lock, flags);
    list_for_each_entry(curr, &target_progs_list, list) {
        if (strncmp(curr->prog, new_node->prog, TASK_COMM_LEN) == 0) {
            spin_unlock_irqrestore(&config_lock, flags);
            kfree(new_node); 
            return 0;
        }
    }
    list_add_rcu(&new_node->list, &target_progs_list);
    num_target_progs++;
    spin_unlock_irqrestore(&config_lock, flags);
    
    return 0;
}

int throttler_remove_prog(const char *prog) {
    struct target_prog_node *curr;
    unsigned long flags;
    bool found = false;

    if (!prog) return -EINVAL;

    spin_lock_irqsave(&config_lock, flags);
    
    list_for_each_entry(curr, &target_progs_list, list) {
        if (strncmp(curr->prog, prog, TASK_COMM_LEN) == 0) { 
            list_del_rcu(&curr->list);
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
    int n = 0;

    if (!buf || max <= 0) return -EINVAL;
    
    rcu_read_lock();
    
    list_for_each_entry_rcu(curr, &target_uids_list, list) {
        if (n >= max) break;
        buf[n++] = curr->uid;
    }
    
    rcu_read_unlock();
    
    return n;
}

int throttler_get_progs(char (*buf)[TASK_COMM_LEN], int max) {
    struct target_prog_node *curr;
    int n = 0;

    if (!buf || max <= 0) return -EINVAL;

    rcu_read_lock();
    list_for_each_entry_rcu(curr, &target_progs_list, list) {
        if (n >= max) break;
        strscpy(buf[n++], curr->prog, TASK_COMM_LEN);
    }
    rcu_read_unlock();
    
    return n;
}

void throttler_config_cleanup(void) {
    struct target_uid_node *uid_curr;
    struct target_uid_node *uid_tmp;
    struct target_prog_node *prog_curr;
    struct target_prog_node *prog_tmp;

    list_for_each_entry_safe(uid_curr, uid_tmp, &target_uids_list, list) {
        list_del_rcu(&uid_curr->list);
        kfree_rcu(uid_curr, rcu);
    }
    
    list_for_each_entry_safe(prog_curr, prog_tmp, &target_progs_list, list) {
        list_del_rcu(&prog_curr->list);
        kfree_rcu(prog_curr, rcu);
    }
    rcu_barrier(); //serve poichè a causa delle kfree-rcu
}

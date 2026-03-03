#include <linux/module.h>
#include "throttler_internal.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicola Violante");
MODULE_DESCRIPTION("Syscall throttler");

static int __init throttler_init(void) {
    printk(KERN_INFO "%s: Module initialization...\n", MODNAME);

    throttler_core_init(); //inizializzazione delle strutture interne che servono al funzionamento del modulo (throttler_core.c)

    if (throttler_memory_init() != 0) { //ricerca system call table e installazione trampolino (throttler_memory.c)
        printk(KERN_ERR "%s: System call table hack failed \n", MODNAME);
        return -1;
    }

    if (throttler_chrdev_init() != 0) { //registrazione device (/dev/syscall_throttler) (throttler_chdev.c)
        printk(KERN_ERR "%s: Character device registration failed.\n", MODNAME);
        throttler_memory_cleanup();
        return -1;
    }

    printk(KERN_INFO "%s: Module successfully loaded.\n", MODNAME);
    return 0;
}

static void __exit throttler_exit(void) {
    printk(KERN_INFO "%s: Module deregistration...\n", MODNAME);

    throttler_chrdev_cleanup();
    throttler_memory_cleanup();
    throttler_core_cleanup();
    throttler_config_cleanup();

    printk(KERN_INFO "%s: Module successfully removed.\n", MODNAME);
}

module_init(throttler_init);
module_exit(throttler_exit);

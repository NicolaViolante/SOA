#include <linux/module.h>
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/slab.h> 

// Nomi utilizzati per udev e sysfs per creare il device file
#define DEVICE_NAME  "syscall_throttler"
#define DEVICE_CLASS "throttler_class"

#include "throttler_internal.h"

struct throttler_cdev {
    dev_t        dev;
    struct cdev  cdev;
    struct class *class; // puntatore a sysfs per la creazione del nodo
};

static struct throttler_cdev device;

extern long throttler_ioctl_dispatcher(struct file *file, unsigned int cmd, unsigned long arg); //dispatcher delle varie operazioni offerte

static const struct file_operations ops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = throttler_ioctl_dispatcher
};

static int throttler_uevent(const struct device *dev, struct kobj_uevent_env *env) { // funzione di callback per uevent
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

int throttler_chrdev_init(void) { //allocazione dinamica majoe e minor
    int err = alloc_chrdev_region(&device.dev, 0, 1, DEVICE_NAME);
    if (err) {
      pr_err("THROTTLER-DEV: Cannot register char device %s, got error %d\n", DEVICE_NAME, err);
      return err;
    }
    
    cdev_init(&device.cdev, &ops); //inizializzazione struttura cdev e collegamento a fileops
    device.cdev.owner = THIS_MODULE;
    err = cdev_add(&device.cdev, device.dev, 1); //registrazione cdev nel kernel
    if (err) {
      pr_err("THROTTLER-DEV: Cannot add device %d:%d, got error %d\n", MAJOR(device.dev), MINOR(device.dev), err);
      goto out; //pulizia region
    }

    struct class *device_class = class_create(DEVICE_CLASS); //crea classe in sysfs -> serve affinché udev crei file in /dev

    if (IS_ERR(device_class)) {
        err = PTR_ERR(device_class);
        pr_err("THROTTLER-DEV:Cannot create class %s, got error %d\n", DEVICE_CLASS, err);
        goto out2; //pulisce cdev e region
    }
    
    device_class->dev_uevent = throttler_uevent; //iniezione funzione di callback
    device.class = device_class;
    
    // crea /dev/syscall_throttler
    struct device *dp = device_create(device.class, NULL, device.dev, NULL, DEVICE_NAME);
    if (IS_ERR(dp)) {
        err = PTR_ERR(dp);
        pr_err("THROTTLER-DEV: Cannot create device /dev/%s, got error %d\n", DEVICE_NAME, err);
        goto out3; // pulisce tutto
    }
    
    pr_info("THROTTLER-DEV: Device /dev/%s successfullty initialized!\n", DEVICE_NAME);
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
    if (device.class) {
        device_destroy(device.class, device.dev); // distrugge nodo (/dev)
        class_destroy(device.class); // distrugge classe (/sys/class)
        device.class = NULL;
    }
    cdev_del(&device.cdev); // rimuove il cdev
    unregister_chrdev_region(device.dev, 1); //libera regione di major e minor allocata
    device.dev = 0;
}

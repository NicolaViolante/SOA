/* throttler_chrdev.c - Registrazione e gestione del Character Device */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/slab.h> 

#include "throttler_chrdev.h"

#define DEVICE_NAME  "syscall_throttler"
#define DEVICE_CLASS "throttler_class"

struct throttler_cdev {
    dev_t        dev;
    struct cdev  cdev;
    struct class *class;
};

static struct throttler_cdev device;

/* Importiamo la funzione di smistamento IOCTL dall'altro file */
extern long throttler_ioctl_dispatcher(struct file *file, unsigned int cmd, unsigned long arg);

static const struct file_operations ops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = throttler_ioctl_dispatcher
};

static int throttler_uevent(const struct device *dev, struct kobj_uevent_env *env) {
    /* Impostiamo i permessi del device node a rw-rw-rw- */
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
      pr_err("Cannot add device %d:%d, got error %d\n", MAJOR(device.dev), MINOR(device.dev), err);
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
    if (device.class) {
        device_destroy(device.class, device.dev);
        class_destroy(device.class);
        device.class = NULL;
    }
    cdev_del(&device.cdev);
    unregister_chrdev_region(device.dev, 1);
    device.dev = 0;
}

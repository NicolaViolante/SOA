#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

#include "../header/throttler_ioctl.h"

#define DEVICE_PATH "/dev/syscall_throttler"

void print_usage(char *prog) {
    printf("\nHow to use: %s <command> [argument]\n", prog);
    
    printf("\n[ON/OFF AND LIMITATIONS]\n");
    printf("  on              - Turn on monitor\n");
    printf("  off             - Turn off monitor and reset stats\n");
    printf("  limit <N>       - Set limit syscall/sec to N\n");
    
    printf("\n[HOOKING]\n");
    printf("  sys <N>         - Hook syscall number N\n");
    printf("  unsys <N>       - Unhook syscall number N\n");
    printf("  prog <name>     - Add <name> to monitored programs\n");
    printf("  unprog <name>   - Remove <name> from monitored programs\n");
    printf("  uid <ID>        - Add UID <ID> to monitored users\n");
    printf("  unuid <ID>      - Remove UID <ID> from monitored users\n");

    printf("\n[READ FROM KERNEL]\n");
    printf("  stats           - Show stats\n");
    printf("  list            - Show monitored syscall, UID, programs\n\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("[-] Error opening /dev/syscall_throttler");
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "on") == 0) {
        if (ioctl(fd, THROTTLER_IOC_MONITOR_ON) < 0) {
            perror("[-] Turn on failed");
        } else {
            printf("[+] Monitor ON.\n");
        }
    } 
    else if (strcmp(argv[1], "off") == 0) {
        if (ioctl(fd, THROTTLER_IOC_MONITOR_OFF) < 0) {
            perror("[-] Turn off failed");
        } else {
            printf("[+] Monitor OFF (Stats reset).\n");
        }
    }
    else if (strcmp(argv[1], "limit") == 0 && argc == 3) {
        int max = atoi(argv[2]);
        if (ioctl(fd, THROTTLER_IOC_SET_MAX, &max) < 0) {
            perror("[-] Error setting limit");
        } else {
            printf("[+] Limit set to %d syscalls/sec.\n", max);
        }
    }
    else if (strcmp(argv[1], "sys") == 0 && argc == 3) {
        int sys = atoi(argv[2]);
        if (ioctl(fd, THROTTLER_IOC_ADD_SYSCALL, &sys) < 0) {
            perror("[-] Error hooking syscall");
        } else {
            printf("[+] Hooked syscall %d.\n", sys);
        }
    }
    else if (strcmp(argv[1], "unsys") == 0 && argc == 3) {
        int sys = atoi(argv[2]);
        if (ioctl(fd, THROTTLER_IOC_REMOVE_SYSCALL, &sys) < 0) {
            perror("[-] Error unhooking syscall");
        } else {
            printf("[+] Unhooked syscall %d.\n", sys);
        }
    }
    else if (strcmp(argv[1], "prog") == 0 && argc == 3) {
        char prog_name[16];
        strncpy(prog_name, argv[2], 15);
        prog_name[15] = '\0';
        if (ioctl(fd, THROTTLER_IOC_ADD_PROG, prog_name) < 0) {
            perror("[-] Error adding program");
        } else {
            printf("[+] Program '%s' added to targets.\n", prog_name);
        }
    }
    else if (strcmp(argv[1], "unprog") == 0 && argc == 3) {
        char prog_name[16];
        strncpy(prog_name, argv[2], 15);
        prog_name[15] = '\0';
        if (ioctl(fd, THROTTLER_IOC_REMOVE_PROG, prog_name) < 0) {
            perror("[-] Error removing program");
        } else {
            printf("[+] Program '%s' removed from targets.\n", prog_name);
        }
    }
    else if (strcmp(argv[1], "uid") == 0 && argc == 3) {
        uid_t uid = (uid_t)atoi(argv[2]);
        if (ioctl(fd, THROTTLER_IOC_ADD_UID, &uid) < 0) {
            perror("[-] Error adding UID");
        } else {
            printf("[+] UID %d added to targets.\n", uid);
        }
    }
    else if (strcmp(argv[1], "unuid") == 0 && argc == 3) {
        uid_t uid = (uid_t)atoi(argv[2]);
        if (ioctl(fd, THROTTLER_IOC_REMOVE_UID, &uid) < 0) {
            perror("[-] Error removing UID");
        } else {
            printf("[+] UID %d removed from targets.\n", uid);
        }
    }
    else if (strcmp(argv[1], "stats") == 0) {
        unsigned long peak_delay = 0;
        struct throttler_peak_info peak_info;
        memset(&peak_info, 0, sizeof(peak_info));
        int peak_blocked = 0;
        int curr_blocked = 0;
        struct throttler_avg_data avg_data = {0, 0};

        ioctl(fd, THROTTLER_IOC_GET_PEAK_DELAY, &peak_delay);
        ioctl(fd, THROTTLER_IOC_GET_PEAK_DELAY_INFO, &peak_info);
        ioctl(fd, THROTTLER_IOC_GET_PEAK_BLOCKED, &peak_blocked);
        ioctl(fd, THROTTLER_IOC_GET_AVG_BLOCKED, &avg_data);
        ioctl(fd, THROTTLER_IOC_GET_BLOCKED_THREAD, &curr_blocked);

        double average_blocked = (avg_data.cnt == 0) ? 0.0 : ((double)avg_data.tot / avg_data.cnt);

        printf("\n--- KERNEL STATISTICS ---\n");
        printf("  Threads currently in queue: %d\n", curr_blocked);
        printf("  Absolute peak delay: %.2f ms (%lu ns)\n", peak_delay / 1000000.0, peak_delay);
        if (peak_delay > 0) 
            printf("  Generated by (Peak Info): Prog: %s, UID: %u\n", peak_info.prog, peak_info.uid);
        printf("  Peak simultaneous blocked threads: %d\n", peak_blocked);
        printf("  Statistical avg. blocked thread: %.2f\n\n", average_blocked);
    }
    else if (strcmp(argv[1], "list") == 0) {
        int num_uids = 0, num_progs = 0, num_sys = 0;
        ioctl(fd, THROTTLER_IOC_GET_NUM_UIDS, &num_uids);
        ioctl(fd, THROTTLER_IOC_GET_NUM_PROGS, &num_progs);
        ioctl(fd, THROTTLER_IOC_GET_NUM_SYSCALLS, &num_sys);

        uid_t *u_buf = malloc(sizeof(uid_t) * (num_uids > 0 ? num_uids : 1));
        char (*p_buf)[16] = malloc(16 * (num_progs > 0 ? num_progs : 1));
        int *s_buf = malloc(sizeof(int) * (num_sys > 0 ? num_sys : 1));

        if (num_uids > 0) ioctl(fd, THROTTLER_IOC_GET_UIDS, u_buf);
        if (num_progs > 0) ioctl(fd, THROTTLER_IOC_GET_PROGS, p_buf);
        if (num_sys > 0) ioctl(fd, THROTTLER_IOC_GET_SYSCALLS, s_buf);

        printf("\n--- CURRENTLY REGISTERED TARGETS ---\n");
        printf("  Monitored syscalls (%d): ", num_sys);
        for(int i=0; i<num_sys; i++) printf("[%d] ", s_buf[i]);
        
        printf("\n  Monitored programs (%d): ", num_progs);
        for(int i=0; i<num_progs; i++) printf("[%s] ", p_buf[i]);
        
        printf("\n  Monitored UIDs (%d): ", num_uids);
        for(int i=0; i<num_uids; i++) printf("[%d] ", u_buf[i]);
        printf("\n\n");

        free(u_buf);
        free(p_buf);
        free(s_buf);
    }
    else {
        printf("[-] Command not recognized or missing parameters.\n");
        print_usage(argv[0]);
    }

    close(fd);
    return EXIT_SUCCESS;
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <stdatomic.h> 

#define SYSCALL_GETPID 39
#define DEFAULT_THREADS 10

atomic_int total_syscalls = 0;

void* spam_worker(void* arg) {
    while (1) {
        syscall(SYSCALL_GETPID);
        atomic_fetch_add(&total_syscalls, 1);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int num_threads = DEFAULT_THREADS;
    
    if (argc > 1) {
        num_threads = atoi(argv[1]);
        if (num_threads <= 0) num_threads = 1;
    }

    printf("=== [%s] Started ===\n", argv[0]);
    printf("%d threads spamming syscall %d...\n\n", num_threads, SYSCALL_GETPID);

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    int *tids = malloc(num_threads * sizeof(int));

    for (int i = 0; i < num_threads; i++) {
        tids[i] = i;
        pthread_create(&threads[i], NULL, spam_worker, &tids[i]);
    }

    while (1) {
        sleep(1);
        int count = atomic_exchange(&total_syscalls, 0);
        printf("[%s] %d syscall done in the last second by %d threads!\n", argv[0], count, num_threads);
    }

    free(threads);
    free(tids);
    return 0;
}

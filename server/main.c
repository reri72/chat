#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "server_con.h"
#include "sslUtils.h"

extern void fill_server_conf_value();
extern int chat_server_init();
extern int chat_server_end();

volatile sig_atomic_t exit_flag = 0;

void sighandle(int signum, siginfo_t *info, void *context);

int main(int argc, char **argv)
{
    struct sigaction sa;
    sa.sa_sigaction = sighandle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fill_server_conf_value();

    if ( chat_server_init() != 0 )
    {
        perror("chat_server_init");
        exit(1);
    }
    
    pthread_t threads[THREAD_POOL_SIZE] = {0,};
    void* (*functions[THREAD_COUNT])(void*) = { thread_accept_client, };
    
    int i;
    for (i = 0; i < THREAD_COUNT; i++)
    {
        if (pthread_create(&threads[i], NULL, functions[i], NULL) != 0)
            perror("Failed to create thread");
    }

    for (i = 0; i < THREAD_COUNT; i++)
    {
        if (pthread_join(threads[i], NULL) != 0)
            perror("Failed to join thread");
    }

    chat_server_end();

    return 0;
}

void sighandle(int signum, siginfo_t *info, void *context)
{
    fprintf(stderr, "Interrupt!! (%d)\n", signum);

    if (info)
    {
        fprintf(stderr, "signal sent by pid: %d\n", info->si_pid);
        fprintf(stderr, "signal code: %d\n", info->si_code);
    }
    
    // cleanup client pool

    exit_flag = 1;
}
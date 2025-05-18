#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "common.h"
#include "server_con.h"
#include "sslUtils.h"
#include "myutils.h"
#include "chat_handle.h"

extern void fill_server_conf_value();
extern void server_db_configure();
extern int chat_server_init();
extern int chat_server_end();

extern MYSQL *conn;
extern _logset _loglevel;

volatile sig_atomic_t exit_flag = 0;

void sighandle(int signum, siginfo_t *info, void *context);

int main(int argc, char **argv)
{
    char pwd[MAX_LOG_FULLPATH_SIZE] = {0,};

    struct sigaction sa;
    struct sigaction sa_pipe;

    memset(&sa, 0, sizeof(sa));
    memset(&sa_pipe, 0, sizeof(sa_pipe));

    if (getcwd(pwd, sizeof(pwd)) == NULL)
    {
        perror("getcwd() error!!");
        exit(0);
    }

    sa.sa_sigaction = sighandle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    sa_pipe.sa_handler = SIG_IGN;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    sigaction(SIGPIPE, &sa_pipe, NULL);

    fill_server_conf_value();
    
    init_log(_loglevel, 4096);
    create_logfile(pwd,"/log/chat_server.log");

    server_db_configure();

    if ( chat_server_init() != 0 )
    {
        perror("chat_server_init");
        exit(1);
    }

    if (load_chatroom(MAX_ROOMS) != SUCCESS)
    {
        LOG_ERR("Failed to create thread");
        exit(1);
    }
    
    pthread_t threads[THREAD_POOL_SIZE] = {0,};
    void* (*functions[THREAD_COUNT])(void*) = { thread_accept_client, thread_delete_old_client};
    
    int i;
    for (i = 0; i < THREAD_COUNT; i++)
    {
        if (pthread_create(&threads[i], NULL, functions[i], NULL) != 0)
            LOG_ERR("Failed to create thread");
    }

    for (i = 0; i < THREAD_COUNT; i++)
    {
        if (pthread_join(threads[i], NULL) != 0)
            LOG_ERR("Failed to join thread");
    }

    chat_server_end();
    destroy_chatroom();
    destroy_log();
    mysql_close(conn);
    mysql_library_end();

    return 0;
}

void sighandle(int signum, siginfo_t *info, void *context)
{
    fprintf(stderr, "Interrupt!! (%d)\n", signum);
    LOG_ERR("Interrupt!! (%d)\n", signum);

    if (info)
    {
        fprintf(stderr, "signal sent by pid: %d\n", info->si_pid);
        fprintf(stderr, "signal code: %d\n", info->si_code);

        LOG_ERR("signal sent by pid: %d\n", info->si_pid);
        LOG_ERR("signal code: %d\n", info->si_code);
    }
    
    destroy_log();

    exit_flag = 1;
}
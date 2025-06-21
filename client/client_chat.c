#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "reriutils.h"

#include "common.h"
#include "client_chat.h"

extern volatile sig_atomic_t exit_flag;
extern int client_sock;
extern char username[MAX_ID_LENGTH];

void running_chat()
{
    system("/usr/bin/clear");

    volatile int run = 1;
    pthread_t recv_thread;

    if (pthread_create(&recv_thread, NULL, recv_msg, (void *)&run) != 0)
        LOG_ERR("pthread_create for recv_msg failed \n");

    while (exit_flag == 0 || run == 1)
    {
        char msg[BUFFER_SIZE] = {0,};
        char formatted_msg[BUFFER_SIZE] = {0,};

        fgets(msg, BUFFER_SIZE, stdin);
        if (strcmp(msg, "quit\n") == 0)
            break;
        
        snprintf(formatted_msg, BUFFER_SIZE-1, "%s: %s", username, msg);
        write(client_sock, formatted_msg, strlen(formatted_msg));
    }

    run = 0;

    int joinret = pthread_join(recv_thread, NULL);
    if (joinret != 0)
        fprintf(stderr, "pthread_join error: %d\n", joinret);

    // 종료 noti ..
}

void *recv_msg(void *arg)
{
    volatile int *run = (volatile int *)arg;
    int str_len = 0;

    while (exit_flag == 0 || *run == 1)
    {
        char rcv_msg[BUFFER_SIZE] = {0,};

        str_len = read(client_sock, rcv_msg, BUFFER_SIZE - 1);
        if (str_len == -1)
            return (void *)0;

        rcv_msg[str_len] = 0;
        fputs(rcv_msg, stdout);
    }

    return NULL;
}
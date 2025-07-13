#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "reriutils.h"

#include "common.h"
#include "client_chat.h"

extern volatile sig_atomic_t exit_flag;

int tcp_client = -1;
extern char username[MAX_ID_LENGTH];

extern char serverip[IP_LEN];
extern unsigned short chatport;

struct sockaddr_in serv_addr = {0,};

void running_chat()
{
    system("/usr/bin/clear");

    volatile int run = 1;
    pthread_t recv_thread;

    tcp_client = create_sock(AF_INET, SOCK_STREAM, 0);
    if (tcp_client < 0)
        return;

    if ( tcp_client_process(tcp_client, chatport, serverip) != 0 )
    {
        LOG_ERR("tcp_client_process() failed \n");
        printf("connect failed \n");
        close_sock(&tcp_client);
        nano_sleep(1,0);
        
        return;
    }

    if (pthread_create(&recv_thread, NULL, recv_msg, (void *)&run) != 0)
        LOG_ERR("pthread_create for recv_msg failed \n");

    while (exit_flag == 0 || run == 1)
    {
        char user_msg[BUFFER_SIZE] = {0,};
        char send_msg[BUFFER_SIZE] = {0,};

        fgets(user_msg, BUFFER_SIZE, stdin);

        snprintf(send_msg, BUFFER_SIZE-1, "%s: %s", username, user_msg);

        ssize_t sendto_len = send(tcp_client, send_msg, strlen(send_msg), 0);
        if (sendto_len <= 0)
            break;
        else if (strstr(send_msg, "quit") != NULL)
            break;
    }

    run = 0;

    int joinret = pthread_join(recv_thread, NULL);
    if (joinret != 0)
        fprintf(stderr, "pthread_join error: %d\n", joinret);

    close_sock(&tcp_client);
}

void *recv_msg(void *arg)
{
    volatile int *run = (volatile int *)arg;
    
    while (exit_flag == 0 && *run == 1)
    {
        char rcv_msg[BUFFER_SIZE] = {0,};

        int valread = recv(tcp_client, rcv_msg, 1024, 0);
        if (valread < 0)
        {
            perror("recv failed !!");
            break;
        }
        else
        {
            printf("%s\n", rcv_msg);
        }

        nano_sleep(0, 100000000);
    }

    *run = 0;

    return NULL;
}
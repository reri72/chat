#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "sslUtils.h"

extern void fill_server_conf_value();
extern int chat_server_init();
extern void chat_server_end();

extern SSL_CTX *ctx;
extern SSL     *ssl;

int server_sock = -1;

void sighandle(int signum);

int main(int argc, char **argv)
{
    fill_server_conf_value();

    if ( chat_server_init() != 0 )
    {
        perror("chat_server_init");
        exit(1);
    }
    

    // do somethings...    


    return 0;
}

void sighandle(int signum)
{
    printf("Interrupt!! (%d) \n", signum);

    chat_server_end();

    exit(0);
}
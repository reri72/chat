#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "socks.h"
#include "sslUtils.h"

#include "menu.h"

extern void fill_client_conf_value();
extern int chat_client_init();
extern void chat_client_end();

extern SSL_CTX *ctx;
extern SSL     *ssl;

int client_sock = -1;

void sighandle(int signum);

int main(int argc, char **argv)
{
    fill_client_conf_value();
    
    if ( chat_client_init() != 0 )
    {
        perror("chat_client_init");
        exit(1);
    }

    while (1)
    {
        int ret = home();
        
        switch (ret)
        {
            case HOME_LOGIN:
            {
                ret = login();
                if (ret == 0)
                    goto ENTRY;
                else
                    exit(0);
            }
            case HOME_JOIN:
            {
                join();
                break;
            }
            case HOME_EXIT:
            default:
            {
                printf("bye \n");
                exit(0);
            }
        }
    }

ENTRY:


    // do somethings

    chat_client_end();

    return 0;
}

void sighandle(int signum)
{
    printf("Interrupt!! (%d) \n", signum);

    chat_client_end();

    exit(0);
}

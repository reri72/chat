#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "client_con.h"
#include "menu.h"

#include "socks.h"
#include "sslUtils.h"

extern void fill_client_conf_value();

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

    fill_client_conf_value();

    if ( chat_client_init() != 0 )
    {
        fprintf(stderr, "chat_client_init() \n");
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

    chat_client_end();

    return 0;
}

void sighandle(int signum, siginfo_t *info, void *context)
{
    fprintf(stderr, "Interrupt!! (%d) \n", signum);

    if (info)
    {
        fprintf(stderr, "signal sent by pid: %d\n", info->si_pid);
        fprintf(stderr, "signal code: %d\n", info->si_code);
    }
    
    chat_client_end();

    exit(0);
}

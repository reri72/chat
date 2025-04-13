#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <signal.h>

#include "client_con.h"
#include "menu.h"

#include "common.h"
#include "socks.h"
#include "sslUtils.h"

volatile sig_atomic_t exit_flag = 0;
char username[MAX_ID_LENGTH] = {0,};

extern void fill_client_conf_value();

void sighandle(int signum, siginfo_t *info, void *context);

int main(int argc, char **argv)
{
    struct sigaction sa_pipe;
    struct sigaction sa;

    memset(&sa_pipe, 0, sizeof(sa_pipe));
    memset(&sa, 0, sizeof(sa));
    
    sa.sa_sigaction = sighandle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    sa_pipe.sa_handler = SIG_IGN;

    sigaction(SIGPIPE, &sa_pipe, NULL);

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
    
    int loginok = -1;
    while (exit_flag == 0)
    {
        int ret = home(loginok);
        switch (ret)
        {
            case HOME_LOGIN:
            {
                loginok = login();
                break;
            }
            case HOME_JOIN:
            {
                join();
                break;
            }
            case HOME_LOGOUT:
            {
                logout();
                loginok = -1;
                break;
            }
            case HOME_CHAT:
            {
                
            }
            case HOME_EXIT1:
            case HOME_EXIT2:
            default:
            {
                printf("bye \n");
                goto ENTRY;
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

    exit_flag = 1;

    nano_sleep(1,0);
    
    chat_client_end();

    exit(0);
}

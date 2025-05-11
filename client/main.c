#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <signal.h>
#include <unistd.h>

#include "client_con.h"
#include "menu.h"

#include "common.h"
#include "reriutils.h"

volatile sig_atomic_t exit_flag = 0;
char username[MAX_ID_LENGTH] = {0,};

extern void fill_client_conf_value();
extern _logset _loglevel;

void sighandle(int signum, siginfo_t *info, void *context);

int main(int argc, char **argv)
{
    char pwd[MAX_LOG_FULLPATH_SIZE] = {0,};

    struct sigaction sa_pipe;
    struct sigaction sa;

    memset(&sa_pipe, 0, sizeof(sa_pipe));
    memset(&sa, 0, sizeof(sa));
    
    if (getcwd(pwd, sizeof(pwd)) == NULL)
    {
        perror("getcwd() error!!");
        exit(0);
    }

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

    init_log(_loglevel, 4096);
    create_logfile(pwd,"/log/chat_client.log");

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
                ret = chat();
                if (ret < 3)
                {
                    if (createroom(ret) == SUCCESS)
                        printf("do somethings.. \n");
                }
                else if (ret == 3)
                {
                    // list
                    goto ENTRY;
                }
                else
                {
                    goto ENTRY;
                }
            } break;
            case HOME_EXIT1:
            case HOME_EXIT2:
            default:
            {
                LOG_DEBUG("bye \n");
                goto ENTRY;
            }
        }
    }

ENTRY:

    chat_client_end();
    destroy_log();

    return 0;
}

void sighandle(int signum, siginfo_t *info, void *context)
{
    fprintf(stderr, "Interrupt!! (%d) \n", signum);
    LOG_ERR("Interrupt!! (%d)\n", signum);

    if (info)
    {
        fprintf(stderr, "signal sent by pid: %d\n", info->si_pid);
        fprintf(stderr, "signal code: %d\n", info->si_code);

        LOG_ERR("signal sent by pid: %d\n", info->si_pid);
        LOG_ERR("signal code: %d\n", info->si_code);
    }

    exit_flag = 1;
    chat_client_end();
    destroy_log();

    nano_sleep(1,0);

    exit(0);
}

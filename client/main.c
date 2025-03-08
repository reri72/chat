#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "menu.h"

void sighandle(int signum);

int main(int argc, char **argv)
{
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

    return 0;
}

void sighandle(int signum)
{
    printf("Interrupt!! (%d) \n", signum);
    exit(0);
}
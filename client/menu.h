#ifndef _MENU_H_
#define _MENU_H_

typedef enum
{
    HOME_LOGIN  = 1,
    HOME_JOIN   = 2,
    HOME_EXIT
} HOME_ENUM;

int home();
int login();
void join();

#endif
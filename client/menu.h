#ifndef _MENU_H_
#define _MENU_H_

typedef enum
{
    HOME_LOGIN  = 1,
    HOME_JOIN   = 2,
    HOME_EXIT
} HOME_ENUM;

#define MAX_ID_LENGTH 20
#define MAX_PASSWORD_LENGTH 20

int home();
int login();
void join();

#endif
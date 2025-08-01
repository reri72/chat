#ifndef _MENU_H_
#define _MENU_H_

typedef enum
{
    HOME_LOGIN  = 1,
    HOME_JOIN,
    HOME_EXIT1,
    HOME_LOGOUT,
    HOME_CHAT,
    HOME_EXIT2
} HOME_ENUM;

int home(int loginok);
int chat();
int createroom(int roomtype, int *roomid);
int login();
void join();
int join_chatroom(int *roomid);
int enter_chatroom(int *roomid);
int logout();

#endif
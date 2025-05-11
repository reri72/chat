#ifndef _CHAT_HANDLE_H_
#define _CHAT_HANDLE_H_

#define MAX_CLIENTS 100
#define MAX_ROOMS   50
#define MAX_USERS_PER_ROOM 10

typedef struct {
    int socket;
    char username[20];
    int current_room_id;
} chatclient;

typedef struct {
    int room_id;
    char name[100];
    int is_group;  // 0: 1:1, 1: 그룹
    int user_count;
    chatclient *users[MAX_USERS_PER_ROOM];
} chatroom;

// -----------------------------------------------------------------------------

void chatroom_create(char *name, int isgroup);

void list_up_room(char *buff);

// -----------------------------------------------------------------------------

#endif
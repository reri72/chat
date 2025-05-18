#ifndef _CHAT_HANDLE_H_
#define _CHAT_HANDLE_H_

#define MAX_USERS_PER_ROOM 10

typedef struct {
    int socket;
    char username[20];
    int current_room_id;
} chatclient_t;

typedef struct chatroom_t
{
    int room_id;
    char name[100];
    int is_group;  // 0: 1:1, 1: 그룹
    int user_count;
    chatclient_t users[MAX_USERS_PER_ROOM];
    struct chatroom_t *next;
} chatroom_t;

typedef struct
{
    int max;
    int size;
    chatroom_t *head;
    chatroom_t *tail;
} roomlist_t;

// -----------------------------------------------------------------------------

int load_chatroom(int max);

void destroy_chatroom();

chatroom_t *setup_room(int room_id, char *name, int is_group, int user_count);

void chatroom_create(char *name, int isgroup);

void list_up_room(char *buff);

// -----------------------------------------------------------------------------

#endif
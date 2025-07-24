#ifndef _CHAT_HANDLE_H_
#define _CHAT_HANDLE_H_

#define MAX_USERS_PER_ROOM 10

typedef struct chatclient chatclient_t;

typedef struct chatclient{
    int sockfd;
    char username[20];
    int current_room_id;
    chatclient_t *next;
} chatclient_t;

typedef struct chatroom_t
{
    int room_id;
    int user_count;
    char name[100];
    int is_group;  // 0: 1:1, 1: 그룹
    time_t create_time;

    chatclient_t *cli_head;
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

void *thread_delete_old_room(void *arg);

int create_chat_sock();

void broadcast_message(chatroom_t *room, int fd, char *message, ssize_t len);

int chatroom_create(char *name, int isgroup);

void list_up_room(char *buff, unsigned int *buflen);

int load_chatroom(int max);

void destroy_chatroom();

void *thread_chatroom(void *arg);

void get_roomid_seq();

chatroom_t *setup_room(int room_id, char *name, int is_group);

chatroom_t *get_room_by_id(int id);

chatroom_t *add_room_user(int room_id, chatclient_t *cli);

void del_room_user(int room_id, chatclient_t *cli);

// -----------------------------------------------------------------------------

#endif
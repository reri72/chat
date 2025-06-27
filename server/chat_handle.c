#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <netinet/in.h>

#include "common.h"

#include "reriutils.h"
#include "chat_handle.h"
#include "server_con.h"

// ------------------------------------------------------------------

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

extern volatile sig_atomic_t exit_flag;
extern MYSQL *conn;

extern unsigned short chatport;
extern char serverip[IP_LEN];

roomlist_t *roomlist = NULL;

int g_roomid = 0;

extern int chat_sock;

int create_chat_sock()
{
    chat_sock = create_sock(AF_INET, SOCK_STREAM, 0);
    if (chat_sock < 0)
        return FAILED;

    sock_set_reuse(chat_sock);

    int ret = tcp_server_process(chat_sock, chatport, serverip);
    if (ret != SUCCESS)
    {
        LOG_ERR("tcp_server_process() failed \n");
        close_sock(&chat_sock);
        return FAILED;
    }
    
    return SUCCESS;
}

int chatroom_create(char *name, int isgroup)
{
    pthread_mutex_lock(&mutex);
    {
        if (roomlist->size >= MAX_ROOMS)
        {
            LOG_WARN("chatroom is full\n");
            pthread_mutex_unlock(&mutex);
            return FAILED;
        }

        chatroom_t *room = setup_room(g_roomid, name, isgroup, 1);

        if (room == NULL)
        {
            LOG_WARN("Failed to setup room\n");
            pthread_mutex_unlock(&mutex);
            return FAILED;
        }

        if (roomlist->head == NULL)
        {
            roomlist->head = room;
            roomlist->tail = room;
        }
        else
        {
            roomlist->tail->next = room;
            roomlist->tail = room;
            roomlist->tail->next = NULL;
        }
        roomlist->size++;
    }
    pthread_mutex_unlock(&mutex);

    return SUCCESS;
}

void list_up_room(char *buff, unsigned int *buflen)
{
    size_t buff_offset = 0;

    *buflen = 0;

    pthread_mutex_lock(&mutex);
    {
        chatroom_t *curroom = roomlist->head;
        while (curroom != NULL)
        {
            char line[512] = {0,};
            int line_len = 0;

            line_len = snprintf(line, sizeof(line), "[room id:%d] name : %s (%s) - in %d person(s)\n",
                                curroom->room_id,
                                curroom->name,
                                curroom->is_group ? "Group" : "1:1",
                                curroom->user_count);

            if (buff_offset + line_len < 60000)
            {
                memcpy(buff + buff_offset, line, line_len);
                buff_offset += line_len;
            }
            else
            {
                break;
            }
            curroom = curroom->next;
        }
    }
    pthread_mutex_unlock(&mutex);

    *buflen = buff_offset;
}

int load_chatroom(int max)
{
    if (max > MAX_ROOMS || max < 1)
        max = MAX_ROOMS;

    roomlist = (roomlist_t *)calloc(max, sizeof(roomlist_t));

    if (roomlist == NULL)
        return -1;
    
    roomlist->max   = max;
    roomlist->size  = 0;
    roomlist->head  = NULL;
    
    MYSQL_RES *result = NULL;
    MYSQL_ROW row;

    char query[256] = {0,};
    snprintf(query, sizeof(query), "SELECT ID, ROOMTYPE, TITLE FROM CHAT_ROOM WHERE DESTROY_DATE IS NULL ");

    if (mysql_query(conn, query))
    {
        LOG_WARN("query failed: %s\n", mysql_error(conn));
        return -1;
    }

    result = mysql_store_result(conn);
    if (result == NULL)
    {
        LOG_WARN("mysql_store_result() failed: %s\n", mysql_error(conn));
        return -1;
    }

    uint64_t num_rows = mysql_num_rows(result);
    if (num_rows > MAX_ROOMS)
        num_rows = MAX_ROOMS;
    
    int i = 0;
    chatroom_t *cur = NULL;
    for (i = 0; i < num_rows; i++)
    {
        row = mysql_fetch_row(result);
        
        chatroom_t *room = setup_room(strtol(row[0], NULL, 10), 
                                        row[2], 
                                        strtol(row[1], NULL, 10),
                                        0);
        if (room == NULL)
            break;

        if (roomlist->head == NULL)
        {
            roomlist->head = room;
            roomlist->tail = room;
            cur = roomlist->head;
            room->next = NULL;            
        }
        else
        {
            cur->next = room;
            roomlist->tail = room;
            roomlist->tail->next = NULL;
            cur = room;
        }
        roomlist->size++;
    }

    mysql_free_result(result);

    return 0;
}

void destroy_chatroom()
{
    if (roomlist == NULL)
        return;
    
    chatroom_t *room = roomlist->head;
    chatroom_t *tmp = NULL;
    while (room != NULL)
    {
        int i = 0;
        if (room == NULL)
            break;

        for (i = 0; i < room->user_count; i++)
        {
            memset(room->users->username, 0, sizeof(room->users->username));
            room->users->current_room_id = -1;
        }
        
        room->room_id = -1;
        memset(room->name, 0, sizeof(room->name));
        room->is_group = -1;
        room->user_count = -1;

        tmp = room->next;
        free(room);
        room = tmp;
    }

    roomlist->head = NULL;
    roomlist->tail = NULL;
    roomlist->max = 0;
    roomlist->size = 0;

    free(roomlist);
    
    return;
}

chatroom_t *setup_room(int room_id, char *name, int is_group, int user_count)
{
    chatroom_t *room = (chatroom_t *)malloc(sizeof(chatroom_t));
    if (room == NULL)
    {
        printf("allocation failed \n");
        return NULL;
    }

    room->room_id = room_id;
    strncpy(room->name, name, sizeof(room->name) - 1);
    room->is_group = is_group == GROUP_ROOM ? 1 : 0;
    room->user_count = 0;
    memset(room->users, 0, sizeof(room->users));
    
    return room;
}

void *thread_chatroom(void *arg)
{
    chatroom_t *room = (chatroom_t *)arg;

    struct sockaddr_in clnt_adr = {0,};
    socklen_t client_addr_size = sizeof(clnt_adr);
    room->users[room->user_count-1].sockfd = accept(chat_sock, (struct sockaddr*)&clnt_adr, &client_addr_size);

    if (room->users[room->user_count-1].sockfd == -1)
    {
        perror("accept() error");
        del_room_user(room->room_id, &room->users[(room->user_count-1)]);
        close_sock(&room->users[room->user_count-1].sockfd);
        return NULL;
    }
    
    ssize_t bytes_read = 0;
    char buffer[BUFFER_SIZE] = {0,};

    while ((bytes_read = recv(room->users[room->user_count-1].sockfd, buffer, BUFFER_SIZE - 1, 0)) > 0)
    {
        buffer[bytes_read] = '\0';
        
        for (int i = 0; i < room->user_count; i++)
        {
            if (room->users[i].sockfd)
            {
                if (send(room->users[i].sockfd, buffer, bytes_read, 0) == -1)
                {
                    perror("send to other client failed");
                }
            }
        }
    }

    close_sock(&room->users[room->user_count-1].sockfd);
    
    del_room_user(room->room_id, &room->users[(room->user_count-1)]);

    return NULL;
}

void get_roomid_seq()
{
    char query[256] = {0,};
    snprintf(query, sizeof(query), "SELECT MAX(ID) FROM CHAT_ROOM ");

    if (mysql_query(conn, query))
    {
        LOG_WARN("query failed: %s\n", mysql_error(conn));
        return;
    }

    MYSQL_RES *result = mysql_store_result(conn);
    if (result == NULL)
    {
        LOG_WARN("mysql_store_result() failed: %s\n", mysql_error(conn));
        return;
    }
    
    if (mysql_num_rows(result) > 0)
    {
        MYSQL_ROW row = mysql_fetch_row(result);
        if (row != NULL && row[0] != NULL)
        {
            g_roomid = strtol(row[0], NULL, 10);
        }
    }
    else
    {
        LOG_WARN("No rows found\n");
    }

    mysql_free_result(result);
}

chatroom_t *add_room_user(int room_id, chatclient_t *cli)
{
    chatroom_t *room = roomlist->head;
    int ret = FAILED;
    
    if (roomlist->size < 1)
        return NULL;
    
    while (room != NULL)
    {
        if (room->room_id == room_id)
        {
            if (room->user_count >= MAX_USERS_PER_ROOM && room->is_group == 1)
                return NULL;
            else if (room->user_count >= 2 && room->is_group == 0)
                return NULL;
            
            memcpy(&room->users[room->user_count++], cli, sizeof(chatclient_t));            
            ret = SUCCESS;
            break;
        }
        room = room->next;
    }
    
    if (ret == SUCCESS)
        return room;

    return NULL;
}

void del_room_user(int room_id, chatclient_t *cli)
{

}
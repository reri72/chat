#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>

#include "common.h"

#include "reriutils.h"
#include "chat_handle.h"

// ------------------------------------------------------------------

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

extern volatile sig_atomic_t exit_flag;

extern MYSQL *conn;

roomlist_t *roomlist = NULL;

void chatroom_create(char *name, int isgroup)
{
    static int roomidx;
    pthread_mutex_lock(&mutex);
    {
        if (roomlist->size >= MAX_ROOMS)
        {
            LOG_WARN("chatroom is full\n");
            pthread_mutex_unlock(&mutex);
            return;
        }

        chatroom_t *room = setup_room(roomidx++, name, isgroup, 1);
        if (roomlist->head == NULL)
        {
            roomlist->head = room;
        }
        else
        {
            roomlist->tail->next = room;
            roomlist->tail = room;
        }
        roomlist->size++;
    }
    pthread_mutex_unlock(&mutex);
}

void list_up_room(char *buff)
{
    pthread_mutex_lock(&mutex);
    {
        chatroom_t *curroom = roomlist->head;
        
        strcat(buff, "==== chatroom list ====\n");
        if (curroom == NULL)
        {
            strcat(buff, " -- NULL --");
        }
        else
        {
            while (curroom != NULL)
            {
                char line[256] = {0,};

                sprintf(line, "[room id:%d] name : %s (%s) - in %d person(s)\n",
                        curroom->room_id,
                        curroom->name,
                        curroom->is_group ? "Group" : "1:1",
                        curroom->user_count);

                strcat(buff, line);

                curroom = curroom->next;
            }
        }
        strcat(buff, "=======================\n");
    }
    pthread_mutex_unlock(&mutex);
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
            cur = roomlist->head;
            room->next = NULL;            
        }
        else
        {
            cur->next = room;
            roomlist->tail = room;
            cur = room;
        }        
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
            close(room->users->socket);
            room->users->socket = -1;

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
    room->is_group = is_group == GROUP_ROOM ? 1 : 0;
    strncpy(room->name, name, sizeof(room->name) - 1);

    room->user_count = 0;
    memset(room->users, 0, sizeof(room->users));
    
    return room;
}


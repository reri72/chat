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

chatclient *clients[MAX_CLIENTS];
int client_count = 0;

chatroom chat_rooms[MAX_ROOMS];
int room_count = 0;

void chatroom_create(char *name, int isgroup)
{
    pthread_mutex_lock(&mutex);
    {
        if (room_count >= MAX_ROOMS)
        {
            LOG_WARN("chatroom is full\n");
            pthread_mutex_unlock(&mutex);
            return;
        }

        chatroom *room = &chat_rooms[room_count];

        room->room_id = room_count;
        strcpy(room->name, name);
        room->is_group = isgroup == GROUP_ROOM ? 1 : 0;
        room->user_count = 0;

        room_count++;
    }
    pthread_mutex_unlock(&mutex);
}

void list_up_room(char *buff)
{
    pthread_mutex_lock(&mutex);
    {
        int i = 0;

        strcat(buff, "== chatroom list ==\n");
        for (i = 0; i < room_count; ++i)
        {
            char line[256] = {0,};
            sprintf(line, "[%d] %s (%s) - in %d person(s)\n",
                    chat_rooms[i].room_id,
                    chat_rooms[i].name,
                    chat_rooms[i].is_group ? "Group" : "1:1",
                    chat_rooms[i].user_count);

            strcat(buff, line);
        }

        if (room_count == 0)
            strcat(buff, " -- NULL --");
    }
    pthread_mutex_unlock(&mutex);
}

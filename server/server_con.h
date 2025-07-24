#ifndef _SERVER_CON_H_
#define _SERVER_CON_H_

#include "reriutils.h"

typedef struct usernode
{
    char id[MAX_ID_LENGTH];
    struct usernode *next;
} usernode_t;

int8_t add_user_to_pool(const char *userid, int8_t len);
void del_user_pool();

int chat_server_init();
int chat_server_end();

int receive_data(SSL *ssl, char *buffer, size_t bufsize);
int send_data(SSL *ssl, char *data, size_t len);

// -----------------------------------------------------------------------------
#define THREAD_POOL_SIZE    5
#define THREAD_COUNT        3

void *thread_accept_client(void* arg);
void *thread_delete_old_client(void *arg);
void *thread_server_communication(void* arg);

// -----------------------------------------------------------------------------

#endif
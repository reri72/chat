#ifndef _SERVER_CON_H_
#define _SERVER_CON_H_

int chat_server_init();
int chat_server_end();

// -----------------------------------------------------------------------------
#define THREAD_POOL_SIZE    5
#define THREAD_COUNT        1

void *thread_accept_client(void* arg);
void *thread_server_communication(void* arg);

// -----------------------------------------------------------------------------

#endif
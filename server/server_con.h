#ifdef _SERVER_CON_H_
#define _SERVER_CON_H_

int chat_server_init();
void chat_server_end();

// -----------------------------------------------------------------------------

void *thread_accept_client();

// -----------------------------------------------------------------------------

int join_con_res();

#endif
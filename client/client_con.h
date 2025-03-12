#ifndef _CLIENT_CON_H_
#define _CLIENT_CON_H_

int chat_client_init();
int chat_client_end();

int join_con_req(const char *id, const char *passwd);

#endif
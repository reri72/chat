#ifndef _CLIENT_CON_H_
#define _CLIENT_CON_H_

int chat_client_init();
int chat_client_end();

int send_data(const unsigned char *buffer, int len);
int recv_data(unsigned char *buffer, int bufsize);

unsigned char *join_con_req(const char *id, const char *passwd, int *buflen);

#endif
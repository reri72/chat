#ifndef _CLIENT_CON_H_
#define _CLIENT_CON_H_

int chat_client_init();
int chat_client_end();

int send_data(unsigned char *buffer, int len);
int recv_data(unsigned char *buffer, int bufsize);

unsigned char *join_req(const char *id, const char *passwd, int *buflen);
void parse_join_res(unsigned char *packet);

unsigned char *login_req(const char *id, const char *passwd, int *buflen);
int parse_login_res(unsigned char *packet);

#endif
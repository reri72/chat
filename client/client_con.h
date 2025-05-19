#ifndef _CLIENT_CON_H_
#define _CLIENT_CON_H_

int chat_client_init();
int chat_client_end();

int send_data(char *buffer, int len);
int recv_data(char *buffer, int bufsize);

char *join_req(const char *id, const char *passwd, int *buflen);
int parse_join_res(char *packet);

char *login_req(const char *id, const char *passwd, int *buflen);
int parse_login_res(char *packet);

char* createroom_req(int type, char *title, char *username, int *buflen);
int parse_createroom_res(char *packet, int *roomid);

char *room_list_req(int *buflen);

#endif
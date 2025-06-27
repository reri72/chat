#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include "stdlib.h"
#include "string.h"

#define FREE(a) \
        if(a != NULL) free(a); \
        a = NULL;

#define WRITE_BUFF(pp, data, size) \
        memcpy(pp, data, size); \
        pp += size;

#define READ_BUFF(buff, pp, size) \
        memcpy(buff, pp, size); \
        pp += size;

#define DEFAULT_SERVER_PORT     7878
#define DEFAULT_CHAT_PORT       8787

#define IP_LEN 16
#define CERT_PATH_LEN 2048
#define KEY_PATH_LEN 2048

#define MAX_ID_LENGTH 20
#define MAX_PASSWORD_LENGTH 50
#define MAX_ROOMTITLE_LENGTH 100

#define PROTO_CREATE_USER       100
#define PROTO_LOGIN_USER        101

#define PROTO_CREATE_ROOM       200
#define PROTO_ROOM_LIST         201
#define PROTO_JOIN_ROOM         202
#define PROTO_ENTER_ROOM        203

#define PRIVATE_ROOM            1
#define GROUP_ROOM              2

#define MAX_ROOMS   50

#define PROTO_REQ   0
#define PROTO_RES   1

#define A_YEAR  (60*60*24*360)
#define A_MONTH (60*60*24*30)
#define A_DAY   (60*60*24)

typedef struct proto_hdr
{
    unsigned short proto;
    char flag;
    unsigned int bodylen;
} proto_hdr_t;

typedef struct client
{
    char ip[16];
    unsigned int ipaddr;
    int sockfd;
    unsigned short port;
    void *ssl;
} client_t;

void read_header(proto_hdr_t *hdr, char *buffer);

#endif
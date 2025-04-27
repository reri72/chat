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

#define DEFAULT_SERVER_PORT 7878

#define IP_LEN 16
#define CERT_PATH_LEN 2048
#define KEY_PATH_LEN 2048

#define MAX_ID_LENGTH 20
#define MAX_PASSWORD_LENGTH 50
#define MAX_ROOMTITLE_LENGTH 100

#define PROTO_CREATE_USER       100
#define PROTO_LOGIN_USER        101
#define PROTO_CREATE_ROOM       102

#define PRIVATE_ROOM            1
#define GROUP_ROOM              2

#define PROTO_REQ   0
#define PROTO_RES   1

typedef struct proto_hdr
{
    unsigned short proto;
    char flag;
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
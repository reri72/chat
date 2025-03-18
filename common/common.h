#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include "stdlib.h"

#define FREE(a) \
        if(a != NULL) free(a); \
        a = NULL;

#define DEFAULT_SERVER_PORT 7878

#define IP_LEN 16
#define CERT_PATH_LEN 2048
#define KEY_PATH_LEN 2048

#define PROTO_CREATE_USER   100

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
} client_t;

#endif
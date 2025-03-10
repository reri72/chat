#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#define DEFAULT_SERVER_PORT 7898

#define CERT_FILE   "cert.crt"
#define KEY_FILE    "cert.key"

#define PROTO_CREATE_USER   100

#define PROTO_REQ   0
#define PROTO_RES   1

typedef struct proto_hdr
{
    unsigned short proto;
    char flag;
} proto_hdr_t;


#endif
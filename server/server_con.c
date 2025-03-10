#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "socks.h"

#include "common.h"

#include "sslUtils.h"
#include "server_con.h"

SSL_CTX *ctx = NULL;
SSL     *ssl = NULL;

extern int server_sock;

extern char serverip[16];
extern unsigned short serverport;

int chat_server_init()
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    init_ssl();

    ctx = create_ctx(1);
    if (ctx == NULL)
    {
        perror("create_ctx");
        goto CLEAN_UP;
    }

    if (configure_ctx(ctx, CERT_FILE, KEY_FILE) < 0)
    {
        perror("configure_ctx");
        goto CLEAN_UP;
    }

    server_sock = create_sock(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("create_sock");
        goto CLEAN_UP;
    }
    
    printf("[%s] sock create success \n", __FUNCTION__);

    return 0;

CLEAN_UP :
    cleanup_ssl(&ssl, &ctx);

    if (server_sock >= 0)
        close_sock(&server_sock);

    exit(1);
}

void chat_server_end()
{
    cleanup_ssl(&ssl, &ctx);

    if (server_sock >= 0)
        close_sock(&server_sock);
}

// -----------------------------------------------------------------------------

void *thread_accept_client()
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    // do somethings...

    return NULL;
}

// -----------------------------------------------------------------------------

int join_con_res()
{
    int ret = 0;
    char *buffer = NULL;
    size_t totlen = 0;
    uint8_t qres = 0;
    proto_hdr_t hdr;

    memset(&hdr, 0, sizeof(proto_hdr_t));

    totlen = sizeof(proto_hdr_t) + sizeof(uint8_t);
    buffer = (char *)calloc(1, totlen);

    hdr.proto   = htons(PROTO_CREATE_USER);
    hdr.flag    = PROTO_RES;

    memcpy(buffer, &hdr, sizeof(proto_hdr_t));

    // qres = ....

    memcpy(buffer, &qres, sizeof(qres));

    // do somethings ..

    return ret;
}
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

extern char serverip[IP_LEN];
extern unsigned short serverport;
extern char certpath[CERT_PATH_LEN];
extern char keypath[KEY_PATH_LEN];

int chat_server_init()
{
    init_ssl();

    ctx = create_ctx(1);
    if (ctx == NULL)
    {
        perror("create_ctx");
        return chat_server_end();
    }

    if (configure_ctx(ctx, certpath, keypath) < 0)
    {
        perror("configure_ctx");
        return chat_server_end();
    }

    server_sock = create_sock(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("create_sock");
        return chat_server_end();
    }

    return 0;
}

int chat_server_end()
{
    if (ssl)
    {
        if (SSL_shutdown(ssl) < 0)
        {
            perror("SSL shutdown failed");
        }
    }
    cleanup_ssl(&ssl, &ctx);

    if (server_sock >= 0)
        close_sock(&server_sock);

    return -1;
}

// -----------------------------------------------------------------------------

void *thread_accept_client()
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
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
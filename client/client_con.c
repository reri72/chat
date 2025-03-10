#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "socks.h"

#include "common.h"

#include "sslUtils.h"
#include "client_con.h"

SSL_CTX *ctx = NULL;
SSL     *ssl = NULL;

extern int client_sock;

extern char clientip[16];
extern char serverip[16];
extern unsigned short serverport;

int chat_client_init()
{
    init_ssl();

    ctx = create_ctx(0);
    if (ctx == NULL)
    {
        perror("create_ctx");
        exit(1);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        perror("SSL_new");
        goto CLEAN_UP;
    }

    client_sock = create_sock(AF_INET, SOCK_STREAM, 0);
    if (client_sock < 0)
    {
        perror("create_sock");
        goto CLEAN_UP;
    }

    if ( tcp_client_process(client_sock, serverport, serverip) != 0 )
    {
        perror("tcp_client_process");
        goto CLEAN_UP;
    }

    if (SSL_set_fd(ssl, client_sock) == 0)
    {
        fprintf(stderr, "SSL_set_fd failed\n");
        goto CLEAN_UP;
    }

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        goto CLEAN_UP;
    }

    printf("[%s] success \n", __FUNCTION__);

    return 0;

CLEAN_UP :
    cleanup_ssl(&ssl, &ctx);

    if (client_sock)
        close_sock(&client_sock);

    exit(1);
}

void chat_client_end()
{
    cleanup_ssl(&ssl, &ctx);

    if (client_sock)
        close_sock(&client_sock);
}

int join_con_req(const char *id, const char *passwd)
{
    int ret = 0;
    char *buffer = NULL;
    size_t totlen = 0;
    uint8_t len = 0;
    proto_hdr_t hdr;

    memset(&hdr, 0, sizeof(proto_hdr_t));

    hdr.proto   = htons(PROTO_CREATE_USER);
    hdr.flag    = PROTO_REQ;
    
    totlen = sizeof(proto_hdr_t) 
                + sizeof(uint8_t) + strlen(id) + 
                + sizeof(uint8_t) + strlen(passwd);
    buffer = (char *)calloc(1, totlen);

    memcpy(buffer, &hdr, sizeof(proto_hdr_t));

    len = strlen(id);
    memcpy(buffer, &len, sizeof(uint8_t));
    memcpy(buffer, id, len);

    len = strlen(passwd);
    memcpy(buffer, &len, sizeof(uint8_t));
    memcpy(buffer, passwd, len);

    // do somethings ..

    return ret;
}
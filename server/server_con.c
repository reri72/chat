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
        int ret = SSL_shutdown(ssl);
        if (ret == 0)
            ret = SSL_shutdown(ssl);

        if (ret < 0)
        {
            int err = SSL_get_error(ssl, ret);
            
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                fprintf(stderr, "SSL_shutdown needs retry \n");
            else if (err == SSL_ERROR_SYSCALL)
                fprintf(stderr, "SSL_shutdown syscall error \n");
            else if (err == SSL_ERROR_SSL)
                fprintf(stderr, "SSL_shutdown protocol error \n");
            else
                fprintf(stderr, "SSL_shutdown failed with error %d \n", err);
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

void test_accept_client()
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    int client_fd = -1;
    
    int ret = tcp_server_process(server_sock, serverport, serverip);
    if (ret == 0)
    {
        printf("Waiting for a client on %s:%d...\n", serverip, serverport);
        client_fd = accept(server_sock, (struct sockaddr*)&addr, &addr_len);
        if (client_fd < 0)
        {
            perror("accept");
            goto TEST_EXIT;
        }

        ssl = SSL_new(ctx);
        if (ssl == NULL)
            goto TEST_EXIT;

        if (SSL_set_fd(ssl, client_fd) == 0)
        {
            fprintf(stderr, "SSL_set_fd failed\n");
            goto TEST_EXIT;
        }

        if (SSL_accept(ssl) <= 0)
        {
            int ssl_err = SSL_get_error(ssl, -1);
            check_ssl_err(ssl_err);
            ERR_print_errors_fp(stderr);
        }
        else
        {
            printf("client accept! \n");
        }
    }

TEST_EXIT:

    if (client_fd >= 0)
        close_sock(&client_fd);
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
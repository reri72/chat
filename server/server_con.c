#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>

#include "socks.h"

#include "common.h"

#include "sockC.h"
#include "server_con.h"

SSL_CTX *ctx = NULL;
SSL     *ssl = NULL;

extern volatile sig_atomic_t exit_flag;

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
        return chat_server_end();

    if (configure_ctx(ctx, certpath, keypath) < 0)
        return chat_server_end();

    server_sock = create_sock(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        fprintf(stderr, "create_sock() failed \n");
        return chat_server_end();
    }
    
    sock_set_reuse(server_sock);
    sock_set_no_delay(server_sock);

    if (sock_set_nonblocking(server_sock) != SUCCESS)
    {
        fprintf(stderr, "sock_set_nonblocking() failed\n");
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

void *thread_accept_client(void* arg)
{
    struct sockaddr_in addr;
    fd_set readfds;

    socklen_t addr_len = sizeof(addr);

    int ret = tcp_server_process(server_sock, serverport, serverip);
    if (ret != SUCCESS)
    {
        fprintf(stderr, "tcp_server_process() failed \n");
        return NULL;
    }

    while (exit_flag == 0)
    {
        int client_sock = -1;
        pthread_t thread;
        struct timeval tm;

        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);

        tm.tv_sec = 1;
        tm.tv_usec = 0;

        int ret = select(server_sock + 1, &readfds, NULL, NULL, &tm);
        if (ret < 0)
        {
            perror("select failed");
            break;
        }
        else if (ret == 0)
        {
            continue;
        }

        if (FD_ISSET(server_sock, &readfds))
        {
            client_sock = accept(server_sock, (struct sockaddr *)&addr, &addr_len);
            if (client_sock < 0)
            {
                perror("accept failed");
                continue;
            }

            client_t *client = (client_t *)calloc(1, sizeof(client_t));
            if (client == NULL)
            {
                fprintf(stderr, "calloc failed \n");
                close_sock(&client_sock);
            }

            strcpy(client->ip, inet_ntoa(addr.sin_addr));
            client->ipaddr = ntohl(addr.sin_addr.s_addr);
            client->sockfd = client_sock;
            client->port = ntohs(addr.sin_port);

#if 0
            printf("new connection(%d) from %s(%u):%u \n", 
                        client->sockfd, client->ip, client->ipaddr, client->port);
#endif

            if (pthread_create(&thread, NULL, thread_client_communication, (void*)client) == 0)
            {
                if (pthread_detach(thread) != 0)
                {
                    perror("pthread_detach");
                    close_sock(&client_sock);
                    FREE(client);
                }
            }
            else
            {
                perror("pthread_create");
                close_sock(&client_sock);
                FREE(client);
            }
        }
    }

    close_sock(&server_sock);

    return NULL;
}

void *thread_client_communication(void* arg)
{
    client_t* client = (client_t*)arg;

    while (exit_flag == 0 && client->sockfd > -1)
    {
        
    }

    close_sock(&client->sockfd);
    FREE(client);

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
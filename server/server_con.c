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
#include "server_sql.h"

SSL_CTX *ctx = NULL;

int receive_data(SSL *ssl, unsigned char *buffer, size_t bufsize);
int send_data(SSL *ssl, unsigned char *data, size_t len);

void close_client_peer(client_t *client);

// ------------------------------------------------------------------
int join_con_res(SSL *ssl, unsigned char *packet);
void join_user_process(unsigned char *packet, int8_t *qres);
int user_login_res(SSL *ssl, unsigned char *packet);
void login_user_process(unsigned char *packet, int8_t *qres);
// ------------------------------------------------------------------

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
        fprintf(stderr, "sock_set_nonblocking");
        return chat_server_end();
    }

    return 0;
}

int chat_server_end()
{
    if (server_sock >= 0)
        close_sock(&server_sock);

    if (ctx != NULL)
        SSL_CTX_free(ctx);
    
    return -1;
}

void close_client_peer(client_t *client)
{
    SSL *ssl = client->ssl;
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
        SSL_free(ssl);
    }

    close_sock(&client->sockfd);
    
    FREE(client);
}

int receive_data(SSL *ssl, unsigned char *buffer, size_t bufsize)
{
    int bytes = 0;

    fd_set readfds;
    struct timeval tv = {1, 0};

    memset(buffer, 0, bufsize);

    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(SSL_get_fd(ssl), &readfds);

        int ret = select(SSL_get_fd(ssl) + 1, &readfds, NULL, NULL, &tv);
        if (ret == -1)
        {
            perror("select");
            break;
        }
        else if (ret == 0)
        {
            continue;
        }

        bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes > 0)
        {
            break;
        }
        else
        {
            int ssl_error = SSL_get_error(ssl, bytes);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            {
                nano_sleep(1,0);
                continue;
            }
            
            ERR_print_errors_fp(stderr);
            break;
        }
    }
    
    return bytes;
}

int send_data(SSL *ssl, unsigned char *data, size_t len)
{
    int sent = 0;

    struct timeval tv = {1, 0};
    fd_set wfds;

    while (sent < len)
    {
        FD_ZERO(&wfds);
        FD_SET(SSL_get_fd(ssl), &wfds);

        if (select(SSL_get_fd(ssl) + 1, NULL, &wfds, NULL, &tv) <= 0)
        {
            perror("select");
            break;
        }

        int ret = SSL_write(ssl, data + sent, len - sent);
        if (ret <= 0)
        {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE)
            {
                nano_sleep(1,0);
                continue;
            }

            fprintf(stderr, "SSL_write failed: %s\n", ERR_reason_error_string(err));
            return -1;
        }
        sent += ret;
    }
    return sent;
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
        SSL *ssl = NULL;
        pthread_t thread;
        struct timeval tm = {1, 0};

        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);

        int ret = select(server_sock + 1, &readfds, NULL, NULL, &tm);
        if (ret < 0)
        {
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
            
            ssl = SSL_new(ctx);
            if (ssl == NULL)
            {
                close_sock(&client_sock);
                fprintf(stderr, "SSL_new failed \n");
                continue;
            }

            if (SSL_set_fd(ssl, client_sock) == 0)
            {
                fprintf(stderr, "SSL_set_fd failed \n");
                SSL_free(ssl); ssl = NULL;
                close_sock(&client_sock);
                continue;
            }

            if (SSL_accept(ssl) <= 0)
            {
                int ssl_err = SSL_get_error(ssl, -1);
                check_ssl_err(ssl_err);
                ERR_print_errors_fp(stderr);

                SSL_free(ssl); ssl = NULL;
                close_sock(&client_sock);
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
            client->ssl = ssl;
            
            printf("new connection(%d) from %s(%u):%u \n", 
                        client->sockfd, client->ip, client->ipaddr, client->port);

            if (pthread_create(&thread, NULL, thread_server_communication, (void*)client) == 0)
            {
                if (pthread_detach(thread) != 0)
                {
                    perror("pthread_detach");
                    close_client_peer(client);
                }
            }
            else
            {
                perror("pthread_create");
                close_client_peer(client);
            }
        }
    }

    return NULL;
}

void *thread_server_communication(void* arg)
{
    client_t *client = (client_t *)arg;
    SSL *ssl = client->ssl;
    unsigned char packet[BUFFER_SIZE] = {0,};

    while (exit_flag == 0)
    {
        proto_hdr_t hdr = {0,0};
        
        int bytes = receive_data(ssl, packet, sizeof(packet));
        if (bytes <= 0)
            break;
        
        read_header(&hdr, packet);
        switch (hdr.proto)
        {
            case PROTO_CREATE_USER:
                {
                    if (join_con_res(ssl, packet))
                        fprintf(stdout, "join response success \n");
                } break;

            case PROTO_LOGIN_USER:
                {
                    if (user_login_res(ssl, packet))
                        fprintf(stdout, "login response success \n");
                } break;

            default:
                break;
        }
    }
    
    printf("exit client : %s \n ", client->ip);
    close_client_peer(client);
    
    return NULL;
}

// -----------------------------------------------------------------------------

int join_con_res(SSL *ssl, unsigned char *packet)
{
    int ret = FAILED;
    unsigned char *buffer = NULL, *pp = NULL;

    size_t totlen = 0;
    int8_t qres = FAILED;
    proto_hdr_t hdr;

    memset(&hdr, 0, sizeof(proto_hdr_t));

    totlen = sizeof(proto_hdr_t) + sizeof(int8_t);
    buffer = (unsigned char *)malloc(totlen);
    if (buffer == NULL)
        return -1;

    pp = buffer;

    hdr.proto   = htons(PROTO_CREATE_USER);
    hdr.flag    = PROTO_RES;

    WRITE_BUFF(pp, &hdr, sizeof(proto_hdr_t));

    join_user_process(packet, &qres);

    WRITE_BUFF(pp, &qres, sizeof(qres));

    ret = send_data(ssl, buffer, totlen);

    FREE(buffer);

    return ret;
}

void join_user_process(unsigned char *packet, int8_t *qres)
{
    unsigned char *pp = packet;

    char id[MAX_ID_LENGTH] = {0,};
    char passwd[MAX_PASSWORD_LENGTH] = {0,};
    uint8_t len = 0;

    pp += sizeof(proto_hdr_t);

    READ_BUFF(&len, pp, sizeof(uint8_t));
    READ_BUFF(id, pp, len);
    
    READ_BUFF(&len, pp, sizeof(uint8_t));
    READ_BUFF(passwd, pp, len);

    *qres = join_user(id, passwd);
}

int user_login_res(SSL *ssl, unsigned char *packet)
{
    int ret = FAILED;
    unsigned char *buffer = NULL, *pp = NULL;

    size_t totlen = 0;
    int8_t qres = FAILED;
    proto_hdr_t hdr;

    memset(&hdr, 0, sizeof(proto_hdr_t));

    totlen = sizeof(proto_hdr_t) + sizeof(int8_t);
    buffer = (unsigned char *)malloc(totlen);
    if (buffer == NULL)
        return -1;

    pp = buffer;

    hdr.proto   = htons(PROTO_LOGIN_USER);
    hdr.flag    = PROTO_RES;

    WRITE_BUFF(pp, &hdr, sizeof(proto_hdr_t));

    login_user_process(packet, &qres);

    WRITE_BUFF(pp, &qres, sizeof(qres));
    
    ret = send_data(ssl, buffer, totlen);

    FREE(buffer);

    return ret;
}

void login_user_process(unsigned char *packet, int8_t *qres)
{
    unsigned char *pp = packet;

    char id[MAX_ID_LENGTH] = {0,};
    char passwd[MAX_PASSWORD_LENGTH] = {0,};
    uint8_t len = 0;

    pp += sizeof(proto_hdr_t);

    READ_BUFF(&len, pp, sizeof(uint8_t));
    READ_BUFF(id, pp, len);
    
    READ_BUFF(&len, pp, sizeof(uint8_t));
    READ_BUFF(passwd, pp, len);

    *qres = login_user(id, passwd);
}

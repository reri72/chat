#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>

#include "socks.h"

#include "common.h"

#include "sockC.h"
#include "client_con.h"

SSL_CTX *ctx = NULL;
SSL     *ssl = NULL;

int client_sock = -1;

extern char clientip[IP_LEN];
extern char serverip[IP_LEN];
extern unsigned short serverport;

extern volatile sig_atomic_t exit_flag;

int chat_client_init()
{
    init_ssl();

    ctx = create_ctx(0);
    if (ctx == NULL)
    {
        fprintf(stderr, "create_ctx failed \n");
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        fprintf(stderr, "SSL_new() failed \n");
        return chat_client_end();
    }

    client_sock = create_sock(AF_INET, SOCK_STREAM, 0);
    if (client_sock < 0)
    {
        fprintf(stderr, "create_sock() failed \n");
        return chat_client_end();
    }

    if ( tcp_client_process(client_sock, serverport, serverip) != 0 )
    {
        fprintf(stderr, "tcp_client_process() failed \n");
        return chat_client_end();
    }

    if (SSL_set_fd(ssl, client_sock) == 0)
    {
        fprintf(stderr, "SSL_set_fd() failed \n");
        return chat_client_end();
    }

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return chat_client_end();
    }

    sock_set_no_delay(client_sock);
    
    return 0;
}

int chat_client_end()
{
    if (ssl)
    {
        int ret = SSL_shutdown(ssl);
        if (ret == 0)
        {
            ret = SSL_shutdown(ssl);
            if (ret < 0)
            {
                int err = SSL_get_error(ssl, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    fprintf(stderr, "SSL shutdown needs retry\n");
                else if (err == SSL_ERROR_SYSCALL)
                    fprintf(stderr, "SSL shutdown syscall error: socket closed early\n");
                else if (err == SSL_ERROR_SSL)
                    fprintf(stderr, "SSL shutdown protocol error\n");
                else
                    fprintf(stderr, "SSL shutdown failed with error %d\n", err);
            }
        }
        else if (ret < 0)
        {
            int err = SSL_get_error(ssl, ret);
            fprintf(stderr, "SSL_shutdown() failed: %d\n", err);
        }
    }

    cleanup_ssl(&ssl, &ctx);

    if (client_sock >= 0)
        close_sock(&client_sock);

    return -1;
}

int send_data(unsigned char *buffer, int len)
{
    int sent = 0;
    while (sent < len)
    {
        int ret = SSL_write(ssl, buffer + sent, len - sent);
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

int recv_data(unsigned char *buffer, int bufsize)
{
    int bytes = 0;
    memset(buffer, 0, bufsize);

    while ((bytes = SSL_read(ssl, buffer, bufsize - 1)) <= 0)
    {
        if (bytes < -1)
        {
            fprintf(stderr, "Error: SSL_read returned unexpected value %d\n", bytes);
            return -1;
        }

        if (ssl == NULL)
        {
            fprintf(stderr, "SSL is NULL\n");
            return -1;
        }

        if (!SSL_is_init_finished(ssl))
        {
            fprintf(stderr, "Handshake not finished. Cannot read/write data \n");
            return -1;
        }

        int err = SSL_get_error(ssl, bytes);
        if (err == SSL_ERROR_WANT_READ)
        {
            nano_sleep(1,0);
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN)
        {
            fprintf(stdout, "Disconnected Server \n");
            return -1;
        }

        fprintf(stderr, "SSL_read failed (%s)\n", ERR_reason_error_string(err));
        return -1;
    }

    buffer[bytes] = '\0';
    return bytes;
}

void *thread_client_communication(void *arg)
{
    while (exit_flag == 0)
    {
        proto_hdr_t hdr = {0,0};
        unsigned char packet[BUFFER_SIZE] = {0,};

        int bytes = recv_data(packet, sizeof(packet));
        if (bytes <= 0)
            break;
        
        read_header(&hdr, packet);
        switch (hdr.proto)
        {
            case PROTO_CREATE_USER:
                {
                    parse_join_res(packet);
                } break;

            case PROTO_LOGIN_USER:
                {
                    parse_login_res(packet);
                } break;

            default:
                break;
        }
    }

    exit_flag = 1;

    return NULL;
}

unsigned char *join_req(const char *id, const char *passwd, int *buflen)
{
    unsigned char *buffer   = NULL;
    unsigned char *p        = NULL;

    size_t totlen = 0;
    uint8_t len = 0;

    proto_hdr_t hdr = {0,};
    
    hdr.proto   = htons(PROTO_CREATE_USER);
    hdr.flag    = PROTO_REQ;
    
    totlen = sizeof(proto_hdr_t) 
                + sizeof(uint8_t) + strlen(id)
                + sizeof(uint8_t) + strlen(passwd);

    buffer = (unsigned char *)calloc(1, totlen);
    if (buffer == NULL)
        return NULL;

    p = buffer;
    *buflen = totlen;

    WRITE_BUFF(p, &hdr, sizeof(proto_hdr_t));

    len = strlen(id);
    WRITE_BUFF(p, &len, sizeof(uint8_t));
    WRITE_BUFF(p, id, len);

    len = strlen(passwd);
    WRITE_BUFF(p, &len, sizeof(uint8_t));
    WRITE_BUFF(p, passwd, len);

    return buffer;
}

void parse_join_res(unsigned char *packet)
{
    unsigned char *p = packet;
    int8_t qres = FAILED;

    p += sizeof(proto_hdr_t);

    memcpy(&qres, p, sizeof(qres));

    if (qres == SUCCESS)
        fprintf(stdout, "join success!! \n");
    else
        fprintf(stdout, "join failed!! \n");
}

unsigned char *login_req(const char *id, const char *passwd, int *buflen)
{
    unsigned char *buffer   = NULL;
    unsigned char *p        = NULL;

    uint8_t len     = 0;
    size_t totlen   = 0;
    
    proto_hdr_t hdr = {0,};

    hdr.proto   = htons(PROTO_LOGIN_USER);
    hdr.flag    = PROTO_REQ;

    totlen = sizeof(proto_hdr_t) 
                + sizeof(uint8_t) + strlen(id)
                + sizeof(uint8_t) + strlen(passwd);

    buffer = (unsigned char *)calloc(1, totlen);
    if (buffer == NULL)
        return NULL;

    p = buffer;
    *buflen = totlen;

    WRITE_BUFF(p, &hdr, sizeof(proto_hdr_t));

    len = strlen(id);
    WRITE_BUFF(p, &len, sizeof(uint8_t));
    WRITE_BUFF(p, id, len);

    len = strlen(passwd);
    WRITE_BUFF(p, &len, sizeof(uint8_t));
    WRITE_BUFF(p, passwd, len);

    return buffer;
}

void parse_login_res(unsigned char *packet)
{
    unsigned char *p = packet;
    int8_t qres = FAILED;

    p += sizeof(proto_hdr_t);

    memcpy(&qres, p, sizeof(qres));

    if (qres == SUCCESS)
        fprintf(stdout, "login success!! \n");
    else
        fprintf(stdout, "login failed!! \n");
}
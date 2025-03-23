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
    cleanup_ssl(&ssl, &ctx);

    if (client_sock >= 0)
        close_sock(&client_sock);

    return -1;
}

int send_data(const unsigned char *buffer, int len)
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
    fd_set read_fds;
    struct timeval timeout;
    int bytes = 0;

    FD_ZERO(&read_fds);
    FD_SET(SSL_get_fd(ssl), &read_fds);

    timeout.tv_sec = 5; // 옵션으로 빼도 될듯
    timeout.tv_usec = 0;

    int ret = select(SSL_get_fd(ssl) + 1, &read_fds, NULL, NULL, &timeout);
    if (ret < 0)
    {
        perror("select() failed");
        return -1;
    }
    else if (ret == 0)
    {
        fprintf(stderr, "timeout.\n");
        return -1;
    }

    memset(buffer, 0, bufsize);
    bytes = SSL_read(ssl, buffer, bufsize - 1);
    if (bytes <= 0)
    {
        int err = SSL_get_error(ssl, bytes);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_WANT_READ )
        {
            fprintf(stderr, "%s \n", ERR_reason_error_string(err));
        }

        fprintf(stderr, "SSL_read failed: %s\n", ERR_reason_error_string(err));
        return -1;
    }

    buffer[bytes] = '\0';
    return bytes;
}

unsigned char *join_con_req(const char *id, const char *passwd, int *buflen)
{
    unsigned char *buffer = NULL;
    size_t totlen = 0;
    uint8_t len = 0;
    proto_hdr_t hdr;
    unsigned char *p = NULL;

    memset(&hdr, 0, sizeof(proto_hdr_t));

    hdr.proto   = htons(PROTO_CREATE_USER);
    hdr.flag    = PROTO_REQ;
    
    totlen = sizeof(proto_hdr_t) 
                + sizeof(uint8_t) + strlen(id) + 
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
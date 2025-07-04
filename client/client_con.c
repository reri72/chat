#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>

#include "common.h"

#include "reriutils.h"
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
        LOG_ERR("create_ctx failed \n");
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        LOG_ERR("SSL_new() failed \n");
        return chat_client_end();
    }

    client_sock = create_sock(AF_INET, SOCK_STREAM, 0);
    if (client_sock < 0)
    {
        LOG_ERR("create_sock() failed \n");
        return chat_client_end();
    }

    if ( tcp_client_process(client_sock, serverport, serverip) != 0 )
    {
        LOG_ERR("tcp_client_process() failed \n");
        return chat_client_end();
    }

    if (SSL_set_fd(ssl, client_sock) == 0)
    {
        LOG_ERR("SSL_set_fd() failed \n");
        return chat_client_end();
    }

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return chat_client_end();
    }

    if (sock_set_nonblocking(client_sock) != SUCCESS)
    {
        LOG_ERR("sock_set_nonblocking");
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
                    LOG_WARN("SSL shutdown needs retry\n");
                else if (err == SSL_ERROR_SYSCALL)
                    LOG_WARN("SSL shutdown syscall error: socket closed early\n");
                else if (err == SSL_ERROR_SSL)
                    LOG_WARN("SSL shutdown protocol error\n");
                else
                    LOG_WARN("SSL shutdown failed with error %d\n", err);
            }
        }
        else if (ret < 0)
        {
            int err = SSL_get_error(ssl, ret);
            LOG_ERR("SSL_shutdown() failed: %d\n", err);
        }
    }

    cleanup_ssl(&ssl, &ctx);

    if (client_sock >= 0)
        close_sock(&client_sock);

    return -1;
}

int send_data(char *buffer, int len)
{
    int sent = 0;

    struct timeval tv = {3, 0};
    fd_set wfds;

    while (sent < len)
    {
        FD_ZERO(&wfds);
        FD_SET(client_sock, &wfds);

        if (select(client_sock + 1, NULL, &wfds, NULL, &tv) <= 0)
        {
            perror("select");
            exit_flag = 1;
            break;
        }

        int ret = SSL_write(ssl, buffer + sent, len - sent);
        if (ret <= 0)
        {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE)
            {
                nano_sleep(1,0);
                continue;
            }

            LOG_ERR("SSL_write failed: %s\n", ERR_reason_error_string(err));
            exit_flag = 1;
            return -1;
        }
        sent += ret;
    }
    return sent;
}

int recv_data(char *buffer, int bufsize)
{
    int bytes = 0;
    int timeout = 0;

    fd_set readfds;
    struct timeval tv = {3, 0};

    memset(buffer, 0, bufsize);

    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(client_sock, &readfds);

        int ret = select(client_sock + 1, &readfds, NULL, NULL, &tv);
        if (ret == -1)
        {
            perror("select");
            exit_flag = 1;
            break;
        }
        else if (ret == 0)
        {
            timeout++;
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
            
            exit_flag = 1;
            ERR_print_errors_fp(stderr);
            break;
        }
    }
    
    return bytes;
}

char *join_req(const char *id, const char *passwd, int *buflen)
{
    char *buffer   = NULL;
    char *p        = NULL;

    size_t totlen = 0;
    uint8_t len = 0;

    proto_hdr_t hdr = {0,};
    
    hdr.proto   = htons(PROTO_CREATE_USER);
    hdr.flag    = PROTO_REQ;
    
    totlen = sizeof(proto_hdr_t) 
                + sizeof(uint8_t) + strlen(id)
                + sizeof(uint8_t) + strlen(passwd);

    buffer = (char *)calloc(1, totlen);
    if (buffer == NULL)
        return NULL;

    p = buffer;
    *buflen = totlen;

    hdr.bodylen = htonl( (totlen - sizeof(proto_hdr_t)) );
    WRITE_BUFF(p, &hdr, sizeof(proto_hdr_t));

    len = strlen(id);
    WRITE_BUFF(p, &len, sizeof(uint8_t));
    WRITE_BUFF(p, id, len);

    len = strlen(passwd);
    WRITE_BUFF(p, &len, sizeof(uint8_t));
    WRITE_BUFF(p, passwd, len);

    return buffer;
}

int parse_join_res(char *packet)
{
    proto_hdr_t hdr = {0,};
    char *p = packet;

    int8_t qres = FAILED;

    memcpy(&hdr, packet, sizeof(proto_hdr_t));
    p += sizeof(proto_hdr_t);

    if ( ntohl(hdr.bodylen) == sizeof(int8_t) )
        memcpy(&qres, p, sizeof(qres));

    return qres;
}

char *login_req(const char *id, const char *passwd, int *buflen)
{
    char *buffer   = NULL;
    char *p        = NULL;

    uint8_t len     = 0;
    size_t totlen   = 0;
    
    proto_hdr_t hdr = {0,};

    hdr.proto   = htons(PROTO_LOGIN_USER);
    hdr.flag    = PROTO_REQ;

    totlen = sizeof(proto_hdr_t) 
                + sizeof(uint8_t) + strlen(id)
                + sizeof(uint8_t) + strlen(passwd);

    buffer = (char *)calloc(1, totlen);
    if (buffer == NULL)
        return NULL;

    p = buffer;
    *buflen = totlen;

    hdr.bodylen = htonl(totlen - sizeof(proto_hdr_t));
    WRITE_BUFF(p, &hdr, sizeof(proto_hdr_t));

    len = strlen(id);
    WRITE_BUFF(p, &len, sizeof(uint8_t));
    WRITE_BUFF(p, id, len);

    len = strlen(passwd);
    WRITE_BUFF(p, &len, sizeof(uint8_t));
    WRITE_BUFF(p, passwd, len);

    return buffer;
}

int parse_login_res(char *packet)
{
    char *ptr = packet;
    int8_t res = FAILED;
    proto_hdr_t hdr = {0,};

    memcpy(&hdr, ptr, sizeof(hdr));
    ptr += sizeof(proto_hdr_t);

    if ( ntohl(hdr.bodylen) == sizeof(int8_t))
        memcpy(&res, ptr, sizeof(int8_t));
    
    return res;
}

char* createroom_req(int type, char *title, char *username, int *buflen)
{
    proto_hdr_t hdr = {0,};

    char *buffer = NULL;
    char *curp = NULL;

    uint8_t len = 0;
    size_t totlen = 0;

    hdr.proto = htons(PROTO_CREATE_ROOM);
    hdr.flag = PROTO_REQ;

    totlen = sizeof(hdr) + sizeof(int)
                            + sizeof(uint8_t) + strlen(title)
                            + sizeof(uint8_t) + strlen(username);
    
    buffer = (char *)malloc(totlen);
    if (buffer == NULL)
        return NULL;

    *buflen = totlen;

    curp = buffer;

    hdr.bodylen = htonl(totlen - sizeof(hdr));
    WRITE_BUFF(curp, &hdr, sizeof(hdr));

    type = htonl(type);
    WRITE_BUFF(curp, &type, sizeof(int));

    len = strlen(title);
    WRITE_BUFF(curp, &len, sizeof(uint8_t));
    WRITE_BUFF(curp, title, len);

    len = strlen(username);
    WRITE_BUFF(curp, &len, sizeof(uint8_t));
    WRITE_BUFF(curp, username, len);

    return buffer;
}

int parse_createroom_res(char *packet, int *roomid)
{
    char *ptr = packet;
    int8_t res = FAILED;

    proto_hdr_t hdr = {0,};

    memcpy(&hdr, packet, sizeof(hdr));
    ptr += sizeof(hdr);

    if ( ntohl(hdr.bodylen) > sizeof(int8_t) )
    {
        memcpy(&res, ptr, sizeof(int8_t));
        ptr += sizeof(int8_t);

        memcpy(roomid, ptr, sizeof(int));
    }
    
    return res;
}

char *room_list_req(int *buflen)
{
    proto_hdr_t hdr = {0,};

    char *buffer    = NULL;
    char *curp      = NULL;

    hdr.proto = htons(PROTO_ROOM_LIST);
    hdr.flag = PROTO_REQ;
    hdr.bodylen = 0;

    buffer = (char *)malloc(sizeof(hdr));
    if (buffer != NULL)
    {
        curp = buffer;
        WRITE_BUFF(curp, &hdr, sizeof(hdr));

        *buflen = (sizeof(hdr));
    }

    return buffer;
}

int parse_room_list_res(char *packet)
{
    proto_hdr_t *hdp = (proto_hdr_t *)packet;
    if ( ntohl(hdp->bodylen) > 0)
    {
        char *pp = packet + sizeof(proto_hdr_t);
        
        LOG_DEBUG("\n%s", pp);
        printf("%s", pp);

        return SUCCESS;
    }
    else
    {
        return FAILED;
    }
}

char *enterroom_req(int *roomid, char *username, size_t *buflen)
{
    proto_hdr_t hdr = {0,};
    uint8_t namelen = strlen(username);
    int id = *roomid;

    char *buffer = NULL;
    char *curp = NULL;
    size_t totlen = sizeof(proto_hdr_t) + 
                    + sizeof(roomid)
                    + namelen
                    + sizeof(uint8_t);
    
    hdr.proto = htons(PROTO_ENTER_ROOM);
    hdr.flag = PROTO_REQ;
    hdr.bodylen = htonl(totlen - sizeof(proto_hdr_t));
    
    buffer = (char *)malloc(totlen);
    if (buffer == NULL)
        return NULL;

    curp = buffer;

    WRITE_BUFF(curp, &hdr, sizeof(hdr));

    id = htonl(id);
    WRITE_BUFF(curp, &id, sizeof(int));
    WRITE_BUFF(curp, &namelen, sizeof(namelen));
    WRITE_BUFF(curp, username, namelen);

    *buflen = totlen;
    
    return buffer;
}

int parse_enterroom_res(char *packet)
{
    proto_hdr_t *hdp = (proto_hdr_t *)packet;
    if ( ntohl(hdp->bodylen) == sizeof(uint8_t))
    {
        uint8_t ret = FAILED;
        char *pp = packet + sizeof(proto_hdr_t);
        
        READ_BUFF(&ret, pp, sizeof(ret));

        return ret;
    }
    else
    {
        return FAILED;
    }
}


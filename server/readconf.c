#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "readconf.h"

char serverip[16] = {0,};
unsigned short serverport = DEFAULT_SERVER_PORT;
char certpath[2048] = {0,};

void fill_server_conf_value()
{
    char curpath[1024] = {0,};
    get_execute_path(curpath, sizeof(curpath));

    char confpath[2048] = {0,};
    snprintf(confpath, sizeof(confpath), "%s%cserver.conf", curpath, '/');

    if (validate_config_file(confpath) == 0)
    {
        perror("Not exist server.conf");
        exit(1);
    }

    char *server_ip = (char *)get_config_value(confpath, "server_ip", TYPE_STRING);
    unsigned short *server_port = (unsigned short *)get_config_value(confpath, "server_port", TYPE_INT);
    char *cert_path = (char *)get_config_value(confpath, "cert_path", TYPE_STRING);

    if (server_ip)
    {
        strcpy(serverip, server_ip);
        free(server_ip);
    }

    if (server_port)
    {
        serverport = *server_port;
        free(server_port);
    }

    if (cert_path)
    {
        strcpy(certpath, cert_path);
        free(cert_path);
    }
}

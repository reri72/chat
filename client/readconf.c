#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "readconf.h"

char clientip[16] = {0,};
char serverip[16] = {0,};
unsigned short serverport = DEFAULT_SERVER_PORT;

void fill_client_conf_value()
{
    char curpath[1024] = {0,};
    get_execute_path(curpath, sizeof(curpath));

    char confpath[2048] = {0,};
    snprintf(confpath, sizeof(confpath), "%s%cclient.conf", curpath, '/');

    if (validate_config_file(confpath) == 0)
    {
        perror("Not exist client.conf");
        exit(1);
    }

    char *client_ip = (char *)get_config_value(confpath, "client_ip", TYPE_STRING);
    char *server_ip = (char *)get_config_value(confpath, "server_ip", TYPE_STRING);
    unsigned short *server_port = (unsigned short *)get_config_value(confpath, "server_port", TYPE_INT);

    if (client_ip)
    {
        printf("client_ip: [%s]\n", client_ip);
        strcpy(clientip, client_ip);
        free(client_ip);
    }

    if (server_ip)
    {
        printf("server_ip: [%s]\n", server_ip);
        strcpy(serverip, server_ip);
        free(server_ip);
    }

    if (server_port)
    {
        printf("server_port: [%u]\n", *server_port);
        serverport = *server_port;
        free(server_port);
    }
}

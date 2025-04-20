#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "reriutils.h"

char clientip[IP_LEN] = {0,};
char serverip[IP_LEN] = {0,};
unsigned short serverport = DEFAULT_SERVER_PORT;
_logset _loglevel = 2;

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
    _logset *log_level = (_logset *)get_config_value(confpath, "loglevel", TYPE_INT);

    if (client_ip)
    {
        strcpy(clientip, client_ip);
        FREE(client_ip);
    }

    if (server_ip)
    {
        strcpy(serverip, server_ip);
        FREE(server_ip);
    }

    if (server_port)
    {
        serverport = *server_port;
        FREE(server_port);
    }

    if (log_level)
    {
        _loglevel = *log_level;
        change_log_level(_loglevel);
        FREE(log_level);
    }
}

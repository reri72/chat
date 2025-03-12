#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "readconf.h"

char serverip[IP_LEN] = {0,};
unsigned short serverport = DEFAULT_SERVER_PORT;
char certpath[CERT_PATH_LEN] = {0,};
char keypath[KEY_PATH_LEN] = {0,};

int server_sock = -1;

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
    char *key_path = (char *)get_config_value(confpath, "key_path", TYPE_STRING);

    if (server_ip)
    {
        strncpy(serverip, server_ip, sizeof(serverip)-1);
        serverip[sizeof(serverip) - 1] = '\0';
        FREE(server_ip);
    }

    if (server_port)
    {
        serverport = *server_port;
        FREE(server_port);
    }

    if (key_path == NULL || cert_path == NULL)
    {
        perror("Not exist cert or key file");
        exit(1);
    }
    
    strncpy(certpath, cert_path, sizeof(certpath) - 1);
    certpath[sizeof(certpath) - 1] = '\0';
    FREE(cert_path);

    strncpy(keypath, key_path, sizeof(keypath) - 1);
    keypath[sizeof(keypath) - 1] = '\0';
    FREE(key_path);
}

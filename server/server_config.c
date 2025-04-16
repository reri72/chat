#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "sockC.h"

MYSQL *conn = NULL;
char serverip[IP_LEN] = {0,};
unsigned short serverport = DEFAULT_SERVER_PORT;
char certpath[CERT_PATH_LEN] = {0,};
char keypath[KEY_PATH_LEN] = {0,};
char db_id[32] = {0,};
char db_passwd[64] = {0,};

int server_sock = -1;

void fill_server_conf_value()
{
    char curpath[1024] = {0,};
    get_execute_path(curpath, sizeof(curpath));

    char confpath[2048] = {0,};
    snprintf(confpath, sizeof(confpath), "%s%cserver.conf", curpath, '/');

    if (validate_config_file(confpath) == 0)
    {
        LOG_ERR("Not exist server.conf\n");
        exit(1);
    }

    char *server_ip = (char *)get_config_value(confpath, "server_ip", TYPE_STRING);
    unsigned short *server_port = (unsigned short *)get_config_value(confpath, "server_port", TYPE_INT);
    char *cert_path = (char *)get_config_value(confpath, "cert_path", TYPE_STRING);
    char *key_path = (char *)get_config_value(confpath, "key_path", TYPE_STRING);
    char *dbid = (char *)get_config_value(confpath, "db_id", TYPE_STRING);
    char *dbpasswd = (char *)get_config_value(confpath, "db_passwd", TYPE_STRING);

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
        LOG_ERR("Not exist cert or key file\n");
        exit(1);
    }

    strncpy(certpath, cert_path, sizeof(certpath) - 1);
    certpath[sizeof(certpath) - 1] = '\0';
    FREE(cert_path);

    strncpy(keypath, key_path, sizeof(keypath) - 1);
    keypath[sizeof(keypath) - 1] = '\0';
    FREE(key_path);

    if (dbid == NULL || dbpasswd == NULL)
    {
        LOG_ERR("Not exist database connecting info \n");
        exit(1);
    }

    strncpy(db_id, dbid, sizeof(db_id) - 1);
    db_id[sizeof(db_id) - 1] = '\0';
    FREE(dbid);

    strncpy(db_passwd, dbpasswd, sizeof(db_passwd) - 1);
    db_passwd[sizeof(db_passwd) - 1] = '\0';
    FREE(dbpasswd);
}

void server_db_configure()
{
    unsigned long flags = CLIENT_COMPRESS;

    mysql_library_init(0, NULL, NULL);
    
	my_init_mysql(&conn);
	my_set_con_option(conn);
    my_con_mysql(conn, serverip, db_id, db_passwd, NULL, 0, flags);

    const char *db_query = "CREATE DATABASE IF NOT EXISTS CHAT";
    if (mysql_query(conn, db_query))
    {
        LOG_ERR("query failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(1);
    }

    const char *db_use_query = "USE CHAT";
    if (mysql_query(conn, db_use_query))
    {
        LOG_ERR("query failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(1);
    }

    const char *db_client_query =  "CREATE TABLE IF NOT EXISTS CLIENT_INFO ("
                                     "ID INT AUTO_INCREMENT PRIMARY KEY, "
                                     "USERNAME VARCHAR(20) NOT NULL, "
                                     "PASSWORD VARCHAR(44) NOT NULL, "
                                     "LAST_LOGIN_TIME TIMESTAMP NULL DEFAULT NULL)";
    if (mysql_query(conn, db_client_query))
    {
        LOG_ERR("query failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(1);
    }
}

#include <stdio.h>

#include "server_sql.h"
#include "myutils.h"

extern MYSQL *conn;

int join_user(const char *id, const char *passwd)
{
    char query[256] = {0,};

    snprintf(query, sizeof(query), 
                "INSERT INTO CLIENT_INFO (USERNAME, PASSWORD) VALUES ('%s', '%s')", 
                id, passwd);

    if (mysql_query(conn, query))
    {
        fprintf(stderr, "query failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    return 0;
}
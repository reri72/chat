#include <stdio.h>
#include <string.h>

#include "server_sql.h"
#include "myutils.h"

extern MYSQL *conn;

int join_user(const char *id, const char *passwd)
{
    MYSQL_RES *result = NULL;
    MYSQL_ROW row;

    char query[256] = {0,};

    snprintf(query, sizeof(query), 
                "SELECT ID FROM CLIENT_INFO WHERE USERNAME = '%s'",
                id);
        
    if (mysql_query(conn, query))
    {
        fprintf(stderr, "query failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    result = mysql_store_result(conn);
    if (result == NULL)
    {
        fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(conn));
        return -1;
    }

    row = mysql_fetch_row(result);
    if (row)
    {
        fprintf(stdout, "already exist user : %s \n", id);
        mysql_free_result(result);
        return -1;
    }

    mysql_free_result(result);

    memset(&query, 0, sizeof(query));
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
#include <stdio.h>
#include <string.h>

#include "server_sql.h"
#include "reriutils.h"

extern MYSQL *conn;

int join_user(const char *id, const char *passwd)
{
    MYSQL_RES *result = NULL;
    MYSQL_ROW row;
    
    char query[256] = {0,};

    unsigned char enc_passwd[EVP_MAX_MD_SIZE] = {0,};
    char *base64passwd = NULL;
    int encpwlen = strlen(passwd);

    SHA256_encrypt((unsigned char *)passwd, encpwlen, enc_passwd);
    
    base64passwd = BASE64_encode(enc_passwd, (EVP_MAX_MD_SIZE/2));
    if (base64passwd == NULL)
    {
        LOG_WARN("password encode failed. \n");
        return -1;
    }
    
    snprintf(query, sizeof(query), 
                "SELECT ID FROM CLIENT_INFO WHERE USERNAME = '%s'",
                id);
        
    if (mysql_query(conn, query))
    {
        LOG_WARN("query failed: %s\n", mysql_error(conn));
        free(base64passwd);
        return -1;
    }

    result = mysql_store_result(conn);
    if (result == NULL)
    {
        LOG_WARN("mysql_store_result() failed: %s\n", mysql_error(conn));
        free(base64passwd);
        return -1;
    }

    row = mysql_fetch_row(result);
    if (row)
    {
        LOG_WARN("already exist user : %s \n", id);
        free(base64passwd);
        mysql_free_result(result);
        return -1;
    }

    mysql_free_result(result);

    memset(&query, 0, sizeof(query));
    snprintf(query, sizeof(query), 
                "INSERT INTO CLIENT_INFO (USERNAME, PASSWORD) VALUES ('%s', '%s')", 
                id, base64passwd);

    if (mysql_query(conn, query))
    {
        LOG_WARN("query failed: %s\n", mysql_error(conn));
        free(base64passwd);
        return -1;
    }
    
    free(base64passwd);
    
    return 0;
}

int login_user(const char *id, const char *passwd)
{
    MYSQL_RES *result = NULL;
    MYSQL_ROW row = NULL;
    
    char    query[256]  = {0,};
    int     ret         = -1;

    unsigned char   enc_passwd[EVP_MAX_MD_SIZE] = {0,};
    char            *base64passwd               = NULL;

    int encpwlen = strlen(passwd);

    SHA256_encrypt((unsigned char *)passwd, encpwlen, enc_passwd);
    
    base64passwd = BASE64_encode(enc_passwd, (EVP_MAX_MD_SIZE/2));
    if (base64passwd == NULL)
    {
        LOG_WARN("password encode failed. \n");
        return ret;
    }
    
    snprintf(query, sizeof(query), 
                "SELECT PASSWORD FROM CLIENT_INFO WHERE USERNAME = '%s'",
                id);
        
    if (mysql_query(conn, query))
    {
        LOG_WARN("query failed: %s\n", mysql_error(conn));
        free(base64passwd);
        return ret;
    }

    result = mysql_store_result(conn);
    if (result == NULL)
    {
        LOG_WARN("mysql_store_result() failed: %s\n", mysql_error(conn));
        free(base64passwd);
        return ret;
    }

    row = mysql_fetch_row(result);
    if (!row)
    {
        LOG_WARN("not exist user : %s \n", id);
        free(base64passwd);
        mysql_free_result(result);
        return ret;
    }

    if ( strstr(base64passwd, row[0]) != NULL )
    {
        ret = SUCCESS;

        memset(&query, 0, sizeof(query));
        snprintf(query, sizeof(query), 
            "UPDATE CLIENT_INFO SET LAST_LOGIN_TIME = now() "
            "WHERE USERNAME = '%s' ", id);
        if (mysql_query(conn, query))
        {
            LOG_WARN("query failed: %s\n", mysql_error(conn));
            ret = FAILED;
        }        
    }
    
    mysql_free_result(result);
    
    free(base64passwd);
    
    return ret;
}

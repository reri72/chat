#include <stdio.h>
#include <string.h>

#include "common.h"
#include "server_sql.h"
#include "reriutils.h"

extern int g_roomid;

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
        FREE(base64passwd);
        return -1;
    }

    result = mysql_store_result(conn);
    if (result == NULL)
    {
        LOG_WARN("mysql_store_result() failed: %s\n", mysql_error(conn));
        FREE(base64passwd);
        return -1;
    }

    row = mysql_fetch_row(result);
    if (row)
    {
        LOG_WARN("already exist user : %s \n", id);
        FREE(base64passwd);
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
        FREE(base64passwd);
        return -1;
    }
    
    FREE(base64passwd);
    
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
        FREE(base64passwd);
        return ret;
    }

    result = mysql_store_result(conn);
    if (result == NULL)
    {
        LOG_WARN("mysql_store_result() failed: %s\n", mysql_error(conn));
        FREE(base64passwd);
        return ret;
    }

    row = mysql_fetch_row(result);
    if (!row)
    {
        LOG_WARN("not exist user : %s \n", id);
        FREE(base64passwd);
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
    
    FREE(base64passwd);
    
    return ret;
}

int create_room(int type, const char *title, const char *id)
{    
    char    query[1024]  = {0,};
    int     ret         = FAILED;
    
    snprintf(query, sizeof(query), 
                "INSERT INTO CHAT_ROOM(ID, ROOMTYPE, TITLE, CREATER, CREATE_DATE) "
                "VALUES(%d, %d, '%s', '%s', now())", 
                ++g_roomid, type, title, id);

    if (mysql_query(conn, query))
    {
        LOG_WARN("query failed: %s\n", mysql_error(conn));
        return ret;
    }

    ret = SUCCESS;
    return ret;
}

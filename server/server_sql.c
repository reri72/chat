#include <stdio.h>
#include <string.h>

#include "common.h"
#include "server_sql.h"
#include "reriutils.h"

extern int g_roomid;

extern MYSQL *conn;

int search_user(const char *id)
{
    MYSQL_STMT *stmt = NULL;
    MYSQL_BIND bind_param[1];
    int row_count = 0;

    stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        LOG_WARN("mysql_stmt_init() failed\n");
        return 2;
    }

    const char *query = "SELECT ID FROM CLIENT_INFO WHERE USERNAME = ?";
    if (mysql_stmt_prepare(stmt, query, strlen(query)))
    {
        LOG_WARN("mysql_stmt_prepare() failed : %s \n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return 2;
    }

    memset(bind_param, 0, sizeof(bind_param));
    bind_param[0].buffer_type = MYSQL_TYPE_STRING;
    bind_param[0].buffer = (char *)id;
    bind_param[0].buffer_length = strlen(id);
    
    if (mysql_stmt_bind_param(stmt, bind_param))
    {
        LOG_WARN("mysql_stmt_bind_param() failed \n");
        mysql_stmt_close(stmt);
        return 2;
    }

    if (mysql_stmt_execute(stmt))
    {
        LOG_WARN("mysql_stmt_execute() failed \n");
        mysql_stmt_close(stmt);
        return 2;
    }

    if (mysql_stmt_store_result(stmt))
    {
        LOG_WARN("mysql_stmt_store_result() failed \n");
        mysql_stmt_close(stmt);
        return 2;
    }

    row_count = mysql_stmt_num_rows(stmt);

    mysql_stmt_close(stmt);

    return row_count;
}

int search_password(const char *id, char *buf)
{
    MYSQL_STMT *stmt;
    MYSQL_BIND bind_param[1];
    MYSQL_BIND bind_res[1];
    char db_password[MAX_PASSWORD_LENGTH] = {0,};
    unsigned long res_length = 0;

    stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        LOG_WARN("mysql_stmt_init() failed\n");
        return FAILED;
    }

    const char *query = "SELECT PASSWORD FROM CLIENT_INFO WHERE USERNAME = ?";
    if (mysql_stmt_prepare(stmt, query, strlen(query)))
    {
        LOG_WARN("mysql_stmt_prepare() failed : %s \n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return FAILED;
    }

    memset(bind_param, 0, sizeof(bind_param));
    bind_param[0].buffer_type = MYSQL_TYPE_STRING;
    bind_param[0].buffer = (char *)id;
    bind_param[0].buffer_length = strlen(id);

    if (mysql_stmt_bind_param(stmt, bind_param))
    {
        LOG_WARN("mysql_stmt_bind_param() failed \n");
        mysql_stmt_close(stmt);
        return FAILED;
    }

    if (mysql_stmt_execute(stmt))
    {
        LOG_WARN("mysql_stmt_execute() failed \n");
        mysql_stmt_close(stmt);
        return FAILED;
    }
    
    memset(bind_res, 0, sizeof(bind_res));
    bind_res[0].buffer_type = MYSQL_TYPE_STRING;
    bind_res[0].buffer = db_password;
    bind_res[0].buffer_length = sizeof(db_password);
    bind_res[0].length = &res_length;

    if (mysql_stmt_bind_result(stmt, bind_res))
    {
        LOG_WARN("mysql_stmt_bind_result() failed \n");
        mysql_stmt_close(stmt);
        return FAILED;
    }

    if (mysql_stmt_fetch(stmt) == 0)
    {
        memcpy(buf, db_password, strlen(db_password));
        mysql_stmt_close(stmt);
        return SUCCESS;
    }

    mysql_stmt_close(stmt);

    return FAILED;
}

int join_user(const char *id, const char *passwd)
{
    MYSQL_STMT *stmt;
    MYSQL_BIND bind_param[2];

    unsigned char enc_passwd[EVP_MAX_MD_SIZE] = {0,};
    char *base64passwd = NULL;
    int encpwlen = strlen(passwd);

    int res = search_user(id);
    if (res != 0)
    {
        if (res == 1) LOG_INFO("%s is exist. \n", id);
        return -1;
    }

    SHA256_encrypt((unsigned char *)passwd, encpwlen, enc_passwd);
    
    base64passwd = BASE64_encode(enc_passwd, (EVP_MAX_MD_SIZE/2));
    if (base64passwd == NULL)
    {
        LOG_WARN("password encode failed. \n");
        return -1;
    }

    stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        LOG_WARN("mysql_stmt_init() failed\n");
        FREE(base64passwd);
        return -1;
    }

    char *query = "INSERT INTO CLIENT_INFO (USERNAME, PASSWORD) VALUES (?, ?)";
    if (mysql_stmt_prepare(stmt, query, strlen(query)))
    {
        LOG_WARN("mysql_stmt_prepare() failed : %s \n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        FREE(base64passwd);
        return -1;
    }
    
    memset(bind_param, 0, sizeof(bind_param));
    bind_param[0].buffer_type = MYSQL_TYPE_STRING;
    bind_param[0].buffer = (char *)id;
    bind_param[0].buffer_length = strlen(id);

    bind_param[1].buffer_type = MYSQL_TYPE_STRING;
    bind_param[1].buffer = (char *)base64passwd;
    bind_param[1].buffer_length = strlen(base64passwd);

    if (mysql_stmt_bind_param(stmt, bind_param))
    {
        LOG_WARN("mysql_stmt_bind_param() failed: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        FREE(base64passwd);
        return -1;
    }

    if (mysql_stmt_execute(stmt))
    {
        LOG_WARN("mysql_stmt_execute() failed: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        FREE(base64passwd);
        return -1;
    }

    mysql_stmt_close(stmt);
    FREE(base64passwd);
    
    return 0;
}

int login_user(const char *id, const char *passwd)
{    
    int             ret                         = FAILED;
    unsigned char   enc_passwd[EVP_MAX_MD_SIZE] = {0,};
    char            *base64passwd               = NULL;
    int             encpwlen                    = strlen(passwd);
    char            tmp_passwd[MAX_PASSWORD_LENGTH] = {0,};

    if (search_user(id) != 1) { return ret; }
    if (search_password(id, tmp_passwd) != 0){ return ret; }

    SHA256_encrypt((unsigned char *)passwd, encpwlen, enc_passwd);
    
    base64passwd = BASE64_encode(enc_passwd, (EVP_MAX_MD_SIZE/2));
    if (base64passwd == NULL)
    {
        LOG_WARN("password encode failed. \n");
        return ret;
    }

    if ( strstr(base64passwd, tmp_passwd) != NULL )
    {
        FREE(base64passwd);

        MYSQL_STMT *stmt;
        MYSQL_BIND bind_param[1];

        const char *query = "UPDATE CLIENT_INFO SET LAST_LOGIN_TIME = now() WHERE USERNAME = ?";

        stmt = mysql_stmt_init(conn);
        if (!stmt)
        {
            LOG_WARN("mysql_stmt_init() failed\n");
            return ret;
        }

        if (mysql_stmt_prepare(stmt, query, strlen(query)))
        {
            LOG_WARN("mysql_stmt_prepare() failed: %s\n", mysql_stmt_error(stmt));
            mysql_stmt_close(stmt);
            return ret;
        }
        
        memset(bind_param, 0, sizeof(bind_param));
        bind_param[0].buffer_type = MYSQL_TYPE_STRING;
        bind_param[0].buffer = (char *)id;
        bind_param[0].buffer_length = strlen(id);

        if (mysql_stmt_bind_param(stmt, bind_param))
        {
            LOG_WARN("mysql_stmt_bind_param() failed: %s\n", mysql_stmt_error(stmt));
            mysql_stmt_close(stmt);
            return ret;
        }

        if (mysql_stmt_execute(stmt))
        {
            LOG_WARN("mysql_stmt_execute() failed: %s\n", mysql_stmt_error(stmt));
            mysql_stmt_close(stmt);
            return ret;
        }

        mysql_stmt_close(stmt);
        ret = SUCCESS; 
    }
    
    FREE(base64passwd);
    
    return ret;
}

int create_room(int type, const char *title, const char *id)
{
    MYSQL_STMT *stmt = NULL;
    MYSQL_BIND bind_param[4];
    int ret = FAILED;

    const char *query = "INSERT INTO CHAT_ROOM(ID, ROOMTYPE, TITLE, CREATER, CREATE_DATE) "
                        "VALUES(?, ?, ?, ?, now())";
    
    stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        LOG_WARN("mysql_stmt_init() failed\n");
        return ret;
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query)))
    {
        LOG_WARN("mysql_stmt_init() failed\n");
        mysql_stmt_close(stmt);
        return 2;
    }

    memset(bind_param, 0, sizeof(bind_param));

    ++g_roomid;

    // buffer를 (char *)로 캐스팅 하는건 관례라고 함.
    // buffer_type에 의해 데이터 읽어감.
    bind_param[0].buffer_type = MYSQL_TYPE_LONG;
    bind_param[0].buffer = (char *)&g_roomid;
    
    bind_param[1].buffer_type = MYSQL_TYPE_LONG;
    bind_param[1].buffer = (char *)&type;

    bind_param[2].buffer_type = MYSQL_TYPE_STRING;
    bind_param[2].buffer = (char *)title;
    bind_param[2].buffer_length = strlen(title);

    bind_param[3].buffer_type = MYSQL_TYPE_STRING;
    bind_param[3].buffer = (char *)id;
    bind_param[3].buffer_length = strlen(id);

    if (mysql_stmt_bind_param(stmt, bind_param))
    {
        LOG_WARN("mysql_stmt_bind_param() failed \n");
        mysql_stmt_close(stmt);
        g_roomid--;
        return ret;
    }

    if (mysql_stmt_execute(stmt))
    {
        LOG_WARN("mysql_stmt_execute() failed \n");
        mysql_stmt_close(stmt);
        g_roomid--;
        return ret;
    }

    mysql_stmt_close(stmt);

    ret = SUCCESS;
    return ret;
}

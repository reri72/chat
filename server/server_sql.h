#ifndef _SERVER_SQL_H_
#define _SERVER_SQL_H_

int join_user(const char *id, const char *passwd);
int login_user(const char *id, const char *passwd);
int create_room(int type, const char *title, const char *id);

#endif
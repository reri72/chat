#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>

#include "common.h"
#include "client_con.h"
#include "menu.h"

#include "reriutils.h"

extern volatile sig_atomic_t exit_flag;
extern char username[MAX_ID_LENGTH];

void echo_off_terminal()
{
    struct termios new_setting;

    tcgetattr(STDIN_FILENO, &new_setting);
    new_setting.c_lflag &= ~ECHO; // ECHO 비활성화
    tcsetattr(STDIN_FILENO, TCSANOW, &new_setting);
}

void echo_on_terminal()
{
    struct termios old_setting;

    tcgetattr(STDIN_FILENO, &old_setting);
    old_setting.c_lflag |= ECHO;  // ECHO 활성화
    tcsetattr(STDIN_FILENO, TCSANOW, &old_setting);
}

void get_id(char *prompt, char *input_buffer, int max_size)
{
    int len = 0;
    while (exit_flag == 0)
    {
        printf("%s", prompt);
        fgets(input_buffer, max_size, stdin);
        
        //fgets 로 문자열을 받으면 끝에 \n 가 생기므로 제거해줌
        input_buffer[strcspn(input_buffer, "\n")] = 0;

        len = strlen(input_buffer);

        if (len < 3 || len > max_size)
        {
            printf("invaild id length (%d/%d)\n", len, max_size);
            memset(input_buffer, 0, max_size);
            continue;
        }
        
        break;
    }
}

void get_password(char *prompt, char *password_buffer, int max_size)
{
    char ch;
    int i = 0;

    echo_off_terminal();
    
    while (exit_flag == 0)
    {
        printf("%s", prompt);
        while (i < max_size - 1)
        {
            ch = getchar();
            if (ch == '\n')  // Enter
            {
                break;
            }
            else if (ch == 127 || ch == 8)  // backspace
            {
                if (i > 0)
                {
                    i--;
                    printf("\b \b");
                }
            }
            else
            {
                password_buffer[i++] = ch;
                printf("*");
            }
        }

        password_buffer[i] = '\0';
        echo_on_terminal();
        printf("\n");

        if (i < 5 || i > MAX_PASSWORD_LENGTH)
        {
            printf("invaild password length (%d/%d) \n", i, MAX_PASSWORD_LENGTH);
            memset(password_buffer, 0, max_size);
            echo_off_terminal();
            i = 0;
            continue;
        }

        break;
    }
}

void get_roomtitle(char *title_buffer, int buffer_size)
{
    int len = 0;
    while (exit_flag == 0)
    {
        printf("ROOM TITLE : ");
        fgets(title_buffer, buffer_size, stdin);
        
        title_buffer[strcspn(title_buffer, "\n")] = 0;

        len = strlen(title_buffer);

        if (len < 3 || len > buffer_size)
        {
            printf("invaild id length (%d/%d)\n", len, buffer_size);
            memset(title_buffer, 0, buffer_size);
            continue;
        }
        
        break;
    }
}

int home(int loginok)
{
    char home_choice[7][8] = {"", "login", "join", "exit", "logout", "chat", "exit"};
    int ret = 0;

    while (1)
    {
        system("/usr/bin/clear");
        puts("======== HELLO CHAT ========");
        if (loginok == SUCCESS)
        {
            printf("* %s \n", username);
            printf("1. %s \n", home_choice[4]);
            printf("2. %s \n", home_choice[5]);
            printf("3. %s \n", home_choice[6]);
            puts("============================");
            puts("your choice > ");

            scanf("%d", &ret);
            ret += 3;

            while (getchar() != '\n');
            if (ret > 3 && ret < 7)
                break;
            
            printf("Invalid menu (%d)\n", ret-3);
        }
        else
        {
            printf("1. %s \n", home_choice[1]);
            printf("2. %s \n", home_choice[2]);
            printf("3. %s \n", home_choice[3]);
            puts("============================");
            puts("your choice > ");

            scanf("%d", &ret);
            while (getchar() != '\n');
            if (ret > 0 && ret < 4)
                break;

            printf("Invalid menu (%d)\n", ret);
        }
        nano_sleep(1, 0);
        ret = 0;
    }

    return ret;
}

int chat()
{
    char chat_choice[5][16] = {"", "create 1:1 room", "create room", "join room", "exit"};
    int ret = 0;

    while (1)
    {
        system("/usr/bin/clear");
        puts("======== CHOICE MENU ========");
        printf("* %s \n", username);
        printf("1. %s \n", chat_choice[1]);
        printf("2. %s \n", chat_choice[2]);
        printf("3. %s \n", chat_choice[3]);
        printf("4. %s \n", chat_choice[4]);
        puts("============================");
        puts("your choice > ");

        scanf("%d", &ret);
        while (getchar() != '\n');
        if (ret > 0 && ret < 5)
            break;

        printf("Invalid menu (%d)\n", ret);
        nano_sleep(1, 0);
    }

    return ret;
}

int createroom(int roomtype, int *roomid)
{
    int res = FAILED;
    char title[MAX_ROOMTITLE_LENGTH] = {0,};

    system("/usr/bin/clear");

    get_roomtitle(title, sizeof(title));

    char *pktbuf    = NULL;
    int pktbuflen   = 0;

    pktbuf = createroom_req(roomtype, title, username, &pktbuflen);
    if (pktbuf)
    {
        if (send_data(pktbuf, pktbuflen) != -1)
        {
            size_t pktsz = (sizeof(proto_hdr_t) + sizeof(int8_t) + sizeof(int));
            char *recvpkt = (char *)malloc(pktsz);
            if (recvpkt)
            {
                if (recv_data(recvpkt, pktsz))
                {
                    if ( (res = parse_createroom_res(recvpkt, roomid)) == SUCCESS )
                    {
                        LOG_DEBUG("create room success (%d)\n", *roomid);
                    }
                }
                FREE(recvpkt);
            }
        }
        FREE(pktbuf);
    }
    
    if (res == FAILED)
    {
        LOG_DEBUG("create room failed (title : %s) \n", title);
        printf("create room failed (title : %s) \n", title);
        nano_sleep(3,0);
    }
    
    return res;
}

int join_chatroom()
{
    int res = FAILED;

    char *pktbuf    = NULL;
    int pktbuflen   = 0;

    system("/usr/bin/clear");

    pktbuf = room_list_req(&pktbuflen);
    if (pktbuf)
    {
        if (send_data(pktbuf, pktbuflen) != -1)
        {
            char recvpkt[65000] = {0,};
            if (recv_data(recvpkt, sizeof(recvpkt)))
            {
                LOG_INFO("\n%s\n", recvpkt + sizeof(proto_hdr_t));
                res = SUCCESS;
            }
        }
        FREE(pktbuf);
    }
    
    if (res == FAILED)
    {
        printf("room list request failed \n");
        nano_sleep(3,0);
    }

    return res;
}

int login()
{
    char id[MAX_ID_LENGTH]              = {0,};
    char password[MAX_PASSWORD_LENGTH]  = {0,};
    
    char *buffer = NULL;
    int len = 0;

    int ret = FAILED;

    system("/usr/bin/clear");

    get_id("ID : ", id, sizeof(id));
    get_password("PASSWORD : ", password, sizeof(password));

    buffer = login_req(id, password, &len);
    if (buffer)
    {
        if (send_data(buffer, len) != -1)
        {
            size_t pktsz = (sizeof(proto_hdr_t) + sizeof(int8_t));
            char *recvpkt = (char *)malloc(pktsz);
            if (recvpkt)
            {
                if (recv_data(recvpkt, pktsz))
                {
                    if ( (ret = parse_login_res(recvpkt)) == SUCCESS )
                    {
                        LOG_DEBUG("login success \n");
                        memcpy(username, id, strlen(id));
                    }
                }
                FREE(recvpkt);
            }
        }
        FREE(buffer);
    }
    
    if (ret == FAILED)
    {
        LOG_DEBUG("login failed (user : %s) \n", id);
        printf("login failed (user : %s) \n", id);
        nano_sleep(3,0);
    }

    return ret;
}

void join()
{
    char id[MAX_ID_LENGTH] = {0,};
    char password[MAX_PASSWORD_LENGTH] = {0,};
    char *buffer = NULL;
    int len = 0;
    int ret = FAILED;

    system("/usr/bin/clear");

    get_id("NEW ID : ", id, sizeof(id));
    get_password("PASSWORD : ", password, sizeof(password));

    buffer = join_req(id, password, &len);
    if (buffer)
    {
        if (send_data(buffer, len) != -1)
        {
            int pktsz = (sizeof(proto_hdr_t) + sizeof(int8_t));
            char *recvpkt = (char *)malloc(pktsz);
            if (recvpkt)
            {
                if (recv_data(recvpkt, pktsz))
                {
                    ret = parse_join_res(recvpkt);
                }
                FREE(recvpkt);
            }
        }
        FREE(buffer);
    }

    if (ret == SUCCESS)
    {
        LOG_INFO("join success (user : %s)\n", id);
        printf("join success (user : %s)\n", id);
    }
    else
    {
        LOG_INFO("join failed (user : %s)\n", id);
        printf("join failed (user : %s)\n", id);
    }

    nano_sleep(3,0);
}

void logout()
{
    memset(&username, 0, sizeof(username));
}

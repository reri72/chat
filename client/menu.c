#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>

#include "common.h"
#include "client_con.h"
#include "menu.h"
#include "utiles.h"

extern volatile sig_atomic_t exit_flag;

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

void get_id(char *prompt, char *input_buffer, int buffer_size, int max_length)
{
    int len = 0;
    while (exit_flag == 0)
    {
        printf("%s", prompt);
        fgets(input_buffer, buffer_size, stdin);
        
        //fgets 로 문자열을 받으면 끝에 \n 가 생기므로 제거해줌
        input_buffer[strcspn(input_buffer, "\n")] = 0;

        len = strlen(input_buffer);

        if (len < 3 || len > max_length)
        {
            printf("invaild id length (%d/%d)\n", len, max_length);
        }
        else
        {
            break;
        }
    }
}

void get_password(char *prompt, char *password_buffer, int buffer_size)
{
    char ch;
    int i = 0;

    echo_off_terminal();
    printf("%s", prompt);

    while (i < buffer_size - 1)
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
        get_password(prompt, password_buffer, buffer_size);
    }
}

int home()
{
    char home_choice[4][8] = {"", "login", "join", "exit"};
    int ret = 0;

    system("/usr/bin/clear");
    
    while (1)
    {
        puts("======== HELLO CHAT ========");
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
        nano_sleep(1, 0);

        system("/usr/bin/clear");
        ret = 0;
    }

    return ret;
}

int login()
{
    return 0;
}

void join()
{
    char id[MAX_ID_LENGTH] = {0,};
    char password[MAX_PASSWORD_LENGTH] = {0,};
    unsigned char *buffer = NULL;
    int len = 0;

    system("/usr/bin/clear");

    puts("============================");
    get_id("NEW ID : ", id, sizeof(id), MAX_ID_LENGTH);
    get_password("PASSWORD : ", password, MAX_PASSWORD_LENGTH);
    puts("============================");

    buffer = join_req(id, password, &len);
    if (buffer == NULL)
    {
        puts("user create failed");
    }
    else
    {
        if (send_data(buffer, len) != -1)
        {
            puts("user create request success");
        }
        else
        {
            puts("user create request failed");
        }
    }

    FREE(buffer);
}
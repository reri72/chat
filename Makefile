CC = gcc
CFLAGS = -Wall -g -O2 -I./libs/reriutils -I./common  
LDFLAGS = -L./libs/reriutils -L/usr/lib64/mysql
LDLIBS = -lreriutils -lmysqlclient -lpthread -lssl -lcrypto 

SERVER_SRC = \
			common/common.c \
			server/server_con.c \
			server/chat_handle.c \
			server/server_config.c \
			server/server_sql.c \
			server/main.c
			
CLIENT_SRC = \
			common/common.c \
			client/client_config.c \
			client/client_con.c \
			client/menu.c \
			client/client_chat.c \
			client/main.c
			

SERVER_OBJ = $(SERVER_SRC:.c=.o)
CLIENT_OBJ = $(CLIENT_SRC:.c=.o)

TARGET = chat_server chat_client

all: $(TARGET)

chat_server: $(SERVER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

chat_client: $(CLIENT_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(SERVER_OBJ) $(CLIENT_OBJ)
	rm -rf pkg

pkg:
	mkdir -p pkg
	mkdir -p pkg/log
	cp chat_server pkg/
	cp chat_client pkg/
	cp etc/* pkg/
	
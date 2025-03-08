CC = gcc
CFLAGS = -Wall -g -O2 -I./libs/reriutils
LDFLAGS = -L./libs/reriutils
LDLIBS = -lreriutils

SERVER_SRC = \
			server/main.c
CLIENT_SRC = \
			client/main.c \
			client/menu.c \

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

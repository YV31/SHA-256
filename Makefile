CC=clang
CFLAGS= -Wall -Wextra -pedantic
BIN=sha256
SRC=sha256.c

all: $(SRC)
	$(CC) -g $^ -o $(BIN) $(CFLAGS) $(LDFLAGS)

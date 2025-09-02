CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic 
LDFLAGS=-lpam

SRC=main.c 

BIN=hyprlogin

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean



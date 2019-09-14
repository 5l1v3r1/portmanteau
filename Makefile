CC = gcc

all: portmanteau

portmanteau:
	$(CC) -lcrypto -l sqlite3 -o portmanteau main.c fuzz.c sql.c macro.c device.c misc.c poc.c
	
clean:
	rm -f portmanteau

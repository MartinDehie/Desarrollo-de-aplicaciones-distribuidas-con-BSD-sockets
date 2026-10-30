CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE

cliente: main.o md5.o http_ip.o
	$(CC) $(CFLAGS) -o cliente main.o md5.o http_ip.o

main.o: main.c md5.h http_ip.h
md5.o: md5.c md5.h
http_ip.o: http_ip.c http_ip.h

.PHONY: clean
clean:
	rm -f *.o cliente
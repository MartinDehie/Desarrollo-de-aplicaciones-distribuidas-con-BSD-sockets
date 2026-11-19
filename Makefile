CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE

cliente: main.o md5.o http_ip.o framing.o pdu.o
	$(CC) $(CFLAGS) -o cliente main.o md5.o http_ip.o framing.o pdu.o

main.o: main.c md5.h http_ip.h framing.h pdu.h
md5.o: md5.c md5.h
http_ip.o: http_ip.c http_ip.h
framing.o: framing.c framing.h
pdu.o:pdu.c pdu.h

.PHONY: clean
clean:
	rm -f *.o cliente
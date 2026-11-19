CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
OBJS = $(addprefix src/, main.o credentials.o auth.o forward.o http_ip.o md5.o framing.o pdu.o)

cliente: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

src/main.o: src/main.c src/credentials.h src/auth.h src/forward.h src/http_ip.h
src/credentials.o: src/credentials.c src/credentials.h
src/auth.o: src/auth.c src/auth.h src/credentials.h src/md5.h
src/forward.o: src/forward.c src/forward.h src/credentials.h src/framing.h src/md5.h src/pdu.h
src/http_ip.o: src/http_ip.c src/http_ip.h
src/md5.o: src/md5.c src/md5.h
src/framing.o: src/framing.c src/framing.h
src/pdu.o: src/pdu.c src/pdu.h

.PHONY: clean
clean:
	rm -f src/*.o cliente

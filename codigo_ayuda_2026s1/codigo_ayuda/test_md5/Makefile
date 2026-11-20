CC = gcc
CFLAGS = -Wall
#CFLAGS = -Wall -Werror

all: test_md5 

test_md5: test_md5.o md5.o
	$(CC) -o $@ $^

md5.o: md5.c
	$(CC) $(CFLAGS) -c $<

test_md5.o: test_md5.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o test_md5

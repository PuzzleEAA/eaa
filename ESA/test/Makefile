CFLAGS = -m64 -g -w -O3 -std=gnu99 -I/usr/local/ssl/include  -I./headers -I/usr/local/lib  -I/usr/local/include -pthread -fno-stack-protector 
LD=-L /usr/lib -lm  -lssl -lcrypto  -L /usr/local/lib/
CC = g++
CLEANFILES = ./*.o
PROGS= test

all: test

test:main.cpp
	${CC} ${CFLAGS} -o $@ $^ $(LD)

clean:
	rm -f ${CLEANFILES}
	rm -f ${PROGS}
	rm -f *~

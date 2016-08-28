
CC	= gcc
CFLAGS	= -Wall -g

mkesb: main.o hexdump.o cper.o
	$(CC) -o mkesb main.o hexdump.o cper.o

main.o: mkesb.h actypes.h actbl.h actbl1.h main.c
	$(CC) $(CFLAGS) -c main.c

cper.o: mkesb.h cper.h cper.c
	$(CC) $(CFLAGS) -c cper.c

hexdump.o: hexdump.c
	$(CC) $(CFLAGS) -c hexdump.c

clean:
	rm -f main.o mkesb cper.o hexdump.o

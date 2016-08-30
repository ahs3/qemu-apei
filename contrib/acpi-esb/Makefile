
CC	= gcc
CFLAGS	= -Wall -g

mkesb: main.o hexdump.o cper.o esb.o
	$(CC) -o mkesb main.o hexdump.o cper.o esb.o

main.o: mkesb.h actypes.h actbl.h actbl1.h main.c
	$(CC) $(CFLAGS) -c main.c

cper.o: mkesb.h cper.h cper.c
	$(CC) $(CFLAGS) -c cper.c

hexdump.o: hexdump.c
	$(CC) $(CFLAGS) -c hexdump.c

esb.o: mkesb.h esb.h esb.c
	$(CC) $(CFLAGS) -c esb.c

clean:
	rm -f mkesb main.o hexdump.o cper.o hexdump.o esb.o

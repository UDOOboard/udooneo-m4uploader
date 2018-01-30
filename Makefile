CC=gcc

all:
	$(CC) -Wall -pedantic -O3 -o mqx_upload_on_m4SoloX mqx_upload_on_m4SoloX.c

clean:
	rm -f mqx_upload_on_m4SoloX *.o


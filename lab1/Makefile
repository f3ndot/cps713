all: htpa

htpa: htpa.o
	gcc htpa.o -o htpa

htpa.o: htpa.c
	gcc -c htpa.c

test: htpa
	./htpa plaintext_message.txt MyKeyGood

test16: htpa
	./htpa plaintext_message.txt MyKeyGood 16

clean:
	rm -rf *.o htpa
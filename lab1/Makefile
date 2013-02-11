all: htpa

htpa: htpa.o
	gcc htpa.o -lssl -lcrypto -o htpa

htpa.o: htpa.c
	gcc -c htpa.c

simple_test: htpa
	./htpa "Hello TA, this is HTPA" MyKeyGood 1

test: htpa
	./htpa plaintext_message.txt MyKeyGood

test16: htpa
	./htpa plaintext_message.txt MyKeyGood 16

clean:
	rm -rf *.o htpa
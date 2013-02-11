all: htpa

htpa: htpa.o
	gcc htpa.o -lssl -lcrypto -o htpa

htpa.o: htpa.c
	gcc -c htpa.c

test_aes_encrypt: htpa
	./htpa -a aes -i 0123456789ABCDEF -e "My message I want to encrypt" "My 256-bit Key is long and great" aes_enc_output.txt

test_aes_decrypt: htpa
	./htpa -a aes -i 0123456789ABCDEF -d aes_enc_output.txt "My 256-bit Key is long and great" aes_plain_output.txt

simple_test: htpa
	./htpa -a htpa -r 1 "Hello TA, this is HTPA" MyKeyGood htpa_enc_output.txt

test: htpa
	./htpa plaintext_message.txt MyKeyGood
	./htpa -a htpa -r 1 plaintext_message.txt MyKeyGood htpa_enc_output.txt

clean:
	rm -rf *.o htpa
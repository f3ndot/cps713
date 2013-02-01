all: htpa

htpa: htpa.o
	gcc htpa.o -o htpa

htpa.o: htpa.c
	gcc -c htpa.c

clean:
	rm -rf *.o htpa
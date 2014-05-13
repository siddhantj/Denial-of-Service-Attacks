all: traffana endhost router

traffana: traffana.c
	gcc -g -Wall -o traffana traffana.c -lpcap

endhost: endhost.c
	gcc -g -Wall -o endhost endhost.c

router: router.c
	gcc -g -Wall -o router router.c -lpcap

clean:
	rm -f *.o traffana endhost router

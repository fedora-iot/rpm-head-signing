ima_lookup.so:
	gcc -c -Wall -Werror -fpic ima_lookup.c -o ima_lookup.o
	gcc -shared -o ima_lookup.so ima_lookup.o

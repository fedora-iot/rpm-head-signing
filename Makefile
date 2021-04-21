all: ima_lookup.so ima_calc_keyid

ima_lookup.so:
	gcc -c -Wall -Werror -fpic ima_lookup.c -o ima_lookup.o
	gcc -shared -o ima_lookup.so ima_lookup.o

ima_calc_keyid:
	gcc -Wall -Werror -fpic ima_calc_keyid.c -o ima_calc_keyid -lcrypto -limaevm

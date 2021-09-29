.PHONY: binaries
binaries: ima_calc_keyid

ima_calc_keyid:
	gcc -Wall -Werror -fpic ima_calc_keyid.c -o ima_calc_keyid -lcrypto -limaevm

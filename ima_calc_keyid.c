#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <imaevm.h>
#include <openssl/pem.h>


int provided_password = 0;
int password_cb(char *buf, int size, int rwflag, void *u) {
    if (provided_password) {
        fprintf(stderr, "Password asked multiple times\n");
        return -1;
    }
    provided_password = 1;
    char *us = (char*)u;
    if (us == NULL) {
        fprintf(stderr, "Password required but not provided\n");
        return -1;
    }

    if (size < strlen(us)) {
        fprintf(stderr, "Password buffer is too small\n");
        return -1;
    }
    strcpy(buf, us);
    buf[strlen(us)] = '\0';
    return strlen(us);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <public|private> <key-path> [key_passphrase]\n", argv[0]);
        return 1;
    }
    char *keytype = argv[1];
    char *keypath = argv[2];
    char *keypass = NULL;
    if (argc >= 4) {
        keypass = argv[3];
    }

    FILE *keyfile = fopen(keypath, "r");
    if (keyfile == NULL) {
        fprintf(stderr, "Error opening keypath %s: %s (%d)\n", keypath, strerror(errno), errno);
        return 1;
    }
    EVP_PKEY *pkey;
    if (strcmp(keytype, "public") == 0) {
        pkey = PEM_read_PUBKEY(keyfile, NULL, password_cb, keypass);
    } else if (strcmp(keytype, "private") == 0) {
        pkey = PEM_read_PrivateKey(keyfile, NULL, password_cb, keypass);
    } else {
        fclose(keyfile);
        fprintf(stderr, "Either public or private\n");
        return 1;
    }
    fclose(keyfile);
    if (pkey == NULL) {
        fprintf(stderr, "Error reading key\n");
        return 1;
    }

    char name[20];
    uint32_t keyid;

    calc_keyid_v2(&keyid, name, pkey);

    printf("keyid str: %s\n", name);

    EVP_PKEY_free(pkey);
    return 0;
}

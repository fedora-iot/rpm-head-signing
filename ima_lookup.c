#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_SIGNATURE_LENGTH 1024

char *
concat_with_sep(const char *a, const char sep, const char *b)
{
    size_t alen = strlen(a);
    char *out = calloc(alen + 1 + strlen(b) + 1, sizeof(char));

    strcpy(out + 0, a);
    out[0 + alen] = sep;
    strcpy(out + 0 + 1 + alen, b);

    return out;
}

char *
build_filename(const char *algo, const unsigned char *hash, int size)
{
    char *output = calloc((2 * size) + 1, sizeof(char));

    char *charout = &output[0];
    for (int i = 0; i < size; i++) {
        charout += sprintf(charout, "%02X", hash[i]);
    }

    return concat_with_sep(algo, '_', output);
}

int
sign_hash(const char *algo, const unsigned char *hash, int size, const char *keyfile, const char *keypass, unsigned char *sig)
{
    const char *presigned_dir = keyfile;
    if (presigned_dir == NULL) {
        fprintf(stderr, "No presigned_dir provided\n");
        return -1;
    }
    char *filename = build_filename(algo, hash, size);
    if (filename == NULL) {
        fprintf(stderr, "Error building filename\n");
        return -1;
    }
    char *filepath = concat_with_sep(presigned_dir, '/', filename);
    if (filepath == NULL) {
        fprintf(stderr, "Error building filepath\n");
        return -1;
    }

    FILE *f = fopen(filepath, "rb");
    if (f == NULL) {
        fprintf(stderr, "Error reading pre-hashed file %s: %d (%s)\n", filepath, errno, strerror(errno));
        return -1;
    }

    size_t numread;
    numread = fread(sig, sizeof(unsigned char), MAX_SIGNATURE_LENGTH, f);

    fclose(f);
    return numread;
}

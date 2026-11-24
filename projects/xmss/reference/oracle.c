/* Deterministic fixture driver for the pinned upstream XMSS C reference.
 * Every seed is public. This program is never a wallet signer. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "xmss.h"

enum { KEY_BYTES = 68, STATE_BYTES = 136, MESSAGE_BYTES = 32, SIG_BYTES = 2500 };

void randombytes(unsigned char *out, unsigned long long size)
{
    for (unsigned long long i = 0; i < size; ++i) {
        out[i] = (unsigned char)i;
    }
}

static int generate_key(const char *path)
{
    unsigned char key[KEY_BYTES], state[STATE_BYTES];
    if (xmss_keypair(key, state, 1) != 0) {
        return 1;
    }
    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        return 1;
    }
    size_t count = fwrite(state, 1, sizeof(state), file);
    if (fclose(file) != 0 || count != sizeof(state)) {
        return 1;
    }
    return fwrite(key, 1, sizeof(key), stdout) != sizeof(key);
}

static int generate_vectors(const char *path)
{
    unsigned char key[KEY_BYTES], state[STATE_BYTES];
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 1;
    }
    size_t count = fread(state, 1, sizeof(state), file);
    if (fclose(file) != 0 || count != sizeof(state)) {
        return 1;
    }
    memcpy(key, state, 4);
    memcpy(key + 4, state + 72, 64);

    unsigned char record[4 + MESSAGE_BYTES], signed_message[SIG_BYTES + MESSAGE_BYTES];
    /* The upstream verifier uses the result buffer as signed-message scratch. */
    unsigned char recovered[SIG_BYTES + MESSAGE_BYTES];
    unsigned int next_index = 0;
    while ((count = fread(record, 1, sizeof(record), stdin)) == sizeof(record)) {
        unsigned int index = ((unsigned int)record[2] << 8) | record[3];
        if (record[0] != 0 || record[1] != 0 || index < next_index || index >= 1023) {
            return 1;
        }
        memcpy(state + 4, record, 4);
        next_index = index + 1;
        unsigned long long signed_size = 0, recovered_size = 0;
        if (xmss_sign(state, signed_message, &signed_size, record + 4, MESSAGE_BYTES) != 0 ||
            signed_size != sizeof(signed_message) ||
            xmss_sign_open(recovered, &recovered_size, signed_message, signed_size, key) != 0 ||
            recovered_size != MESSAGE_BYTES || memcmp(recovered, record + 4, MESSAGE_BYTES) != 0 ||
            fwrite(signed_message, 1, SIG_BYTES, stdout) != SIG_BYTES) {
            return 1;
        }
    }
    return count != 0 || ferror(stdin) || fflush(stdout) != 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        return 1;
    }
    if (strcmp(argv[1], "key") == 0) {
        return generate_key(argv[2]);
    }
    if (strcmp(argv[1], "sign") == 0) {
        return generate_vectors(argv[2]);
    }
    return 1;
}

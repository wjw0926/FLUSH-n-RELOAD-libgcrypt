#include "gcry.h"
#include "common.h"

int main(int argc, char *argv[]) {
    FILE* f;
    void* buf;
    gcry_error_t err = 0;
    gcry_sexp_t params;
    gcry_sexp_t keypair;

    init_gcrypt();
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
    }

    f = fopen("rsa.sp", "wb");
    if (!f) {
        fprintf(stderr, "fopen() failed\n");
        return 0;
    }

    err = gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err) {
        fprintf(stderr, "gcrypt: failed to create rsa params\n");
        return 0;
    }

    err = gcry_pk_genkey(&keypair, params);
    if (err) {
        fprintf(stderr, "gcrypt: failed to create rsa key pair\n");
        return 0;
    }

    printf("RSA key generation complete\n");

    buf = calloc(1, RSA_KEYPAIR_LEN);
    if (!buf) {
        fprintf(stderr, "malloc: could not allocate rsa buffer\n");
        return 0;
    }

    gcry_sexp_sprint(keypair, GCRYSEXP_FMT_CANON, buf, RSA_KEYPAIR_LEN);

    if (fwrite(buf, RSA_KEYPAIR_LEN, 1, f) != 1) {
        fprintf(stderr, "fwrite() failed\n");
        return 0;
    }

    /* Release contexts. */
    gcry_sexp_release(keypair);
    gcry_sexp_release(params);
    free(buf);
    fclose(f);

    return 1;
}

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

    f = fopen("ecc.sp", "wb");
    if (!f) {
        fprintf(stderr, "fopen() failed\n");
        return 0;
    }

    err = gcry_sexp_build(&params, NULL, "(genkey (ecc (curve Ed25519) (flags eddsa)))");
    if (err) {
        fprintf(stderr, "gcrypt: failed to create ecc params\n");
        return 0;
    }

    err = gcry_pk_genkey(&keypair, params);
    if (err) {
        fprintf(stderr, "gcrypt: failed to create ecc key pair\n");
        return 0;
    }

    printf("ECC key generation complete\n");

    buf = calloc(1, ECC_KEYPAIR_LEN);
    if (!buf) {
        fprintf(stderr, "malloc: could not allocate ecc buffer\n");
        return 0;
    }

    gcry_sexp_sprint(keypair, GCRYSEXP_FMT_CANON, buf, ECC_KEYPAIR_LEN);

    if (fwrite(buf, ECC_KEYPAIR_LEN, 1, f) != 1) {
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Libgcrypt */
#include <gcrypt.h>
#include "gcry.h"
#include "common.h"

int encryptText(char *str);

void help(char *progname)
{
    printf("Usage : %s -h -m [msg]\n", progname);
}

int main(int argc, char *argv[]) {
    int opt;
    int optflag=0;
    char str[MAXLINE];

    /* Initialize libgcrypt */
    init_gcrypt_secure();
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
    }

    /* Argument parsing */
    while((opt = getopt(argc, argv, "hm:")) != -1) {
        switch(opt) {
            case 'h':
                help(argv[0]);
                return 1;
            case 'm':
                sprintf(str, "%s", optarg);
                optflag = 1;
                break;
            default:
                help(argv[0]);
                return 1;
        }
    }
    if((str[0] == '\0') && (optflag == 1)) {
        printf ("string error\n");
        return 0;
    }

    if(encryptText(str) == -1) {
        printf("Encrypt text failed\n");
        return -1;
    }

    return 1;
}

int encryptText(char *str) {
    char buf[MAXLINE];
    FILE* f;
    void* rsa_buf;
    gcry_error_t err;
    gcry_mpi_t plain_mpi;
    gcry_mpi_t cipher_mpi;
    gcry_sexp_t plain;
    gcry_sexp_t cipher;
    gcry_sexp_t keypair;
    gcry_sexp_t pkey;
    size_t nwritten = 0;

    /* Load publid-key */
    f = fopen("rsa.sp", "rb");
    if(!f) {
        fprintf(stderr, "fopen() failed\n");
        return -1;
    }

    rsa_buf = calloc(1, RSA_KEYPAIR_LEN);
    if(!rsa_buf) {
        fprintf(stderr, "malloc: could not allocate rsa buffer\n");
        return -1;
    }
    if(fread(rsa_buf, RSA_KEYPAIR_LEN, 1, f) != 1) {
        fprintf(stderr, "fread() failed\n");
        return -1;
    }
    fclose(f);

    err = gcry_sexp_new(&keypair, rsa_buf, RSA_KEYPAIR_LEN, 0);
    free(rsa_buf);
    pkey = gcry_sexp_find_token(keypair, "public-key", 0);
    gcry_sexp_release(keypair);

    memset(buf, 0, MAXLINE);
    strncpy(buf, str, MAXLINE);
    printf("Plain text: %s\n", buf);

    err = gcry_mpi_scan(&plain_mpi, GCRYMPI_FMT_USG, buf, strlen((const char *) buf), NULL);
    if(err) {
        fprintf(stderr, "failed to create a mpi from the message\n");
        return -1;
    }

    err = gcry_sexp_build(&plain, NULL, "(data (flags raw) (value %M))", plain_mpi);
    if(err) {
        fprintf(stderr, "failed to create a sexp from the message\n");
        return -1;
    }

    /* Encrypt the PLAIN using the public key PKEY and store the result as
       a newly created S-expression at CIPHER. */
    err = gcry_pk_encrypt(&cipher, plain, pkey);
    if(err) {
        fprintf(stderr, "gcrypt encryption failed: %s\n", gcry_strsource(err));
        return -1;
    }

    cipher_mpi = gcry_sexp_nth_mpi(gcry_sexp_find_token(cipher, "a", 0), 1, GCRYMPI_FMT_USG);

    memset(buf, 0, MAXLINE);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) &buf, sizeof(buf), &nwritten, cipher_mpi);
    if(err) {
        fprintf(stderr, "failed to stringify cipher mpi\n");
        return -1;
    }

    f = fopen("cipher.txt", "wb");
    if(!f) {
        fprintf(stderr, "fopen() failed\n");
        return -1;
    }

    if(fwrite(buf, MAXLINE, 1, f) != 1) {
        fprintf(stderr, "fwrite() failed\n");
        return -1;
    }
    fclose(f);

    /* Release contexts. */
    gcry_mpi_release(plain_mpi);
    gcry_mpi_release(cipher_mpi);
    gcry_sexp_release(plain);
    gcry_sexp_release(cipher);
    gcry_sexp_release(pkey);

    return 1;
}

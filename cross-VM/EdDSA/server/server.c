#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Libgcrypt */
#include <gcrypt.h>
#include "gcry.h"
#include "common.h"

int signMessage(int cli_sockfd, char *buf) {
    unsigned char r_buf[MAXLINE];
    unsigned char s_buf[MAXLINE];
    FILE* f;
    void* ecc_buf;
    gcry_error_t err;
    gcry_mpi_t r_mpi;
    gcry_mpi_t s_mpi;
    gcry_sexp_t plain;
    gcry_sexp_t sign;
    gcry_sexp_t keypair;
    gcry_sexp_t skey;
    size_t nwritten = 0;

    /* Load private-key */
    f = fopen("ecc.sp", "rb");
    if(!f) {
        fprintf(stderr, "fopen() failed\n");
        return -1;
    }
    ecc_buf = calloc(1, ECC_KEYPAIR_LEN);
    if(!ecc_buf) {
        fprintf(stderr, "malloc: could not allocate ecc buffer\n");
        return -1;
    }
    if(fread(ecc_buf, ECC_KEYPAIR_LEN, 1, f) != 1) {
        fprintf(stderr, "fread() failed\n");
        return -1;
    }
    fclose(f);

    err = gcry_sexp_new(&keypair, ecc_buf, ECC_KEYPAIR_LEN, 0);
    free(ecc_buf);
    skey = gcry_sexp_find_token(keypair, "private-key", 0);
    gcry_sexp_release(keypair);

    err = gcry_sexp_build(&plain, NULL, "(data (flags eddsa) (hash-algo sha512) (value %s))", buf);
    if(err) {
        fprintf(stderr, "failed to create a sexp from the message\n");
        return -1;
    }

    /* Sign the PLAIN using the private key SKEY and store the result as
       a newly created S-expression at SIGN. */
    err = gcry_pk_sign(&sign, plain, skey);
    if (err) {
        fprintf(stderr, "gcrypt signing failed: %s\n", gcry_strsource(err));
        return -1;
    }

    r_mpi = gcry_sexp_nth_mpi(gcry_sexp_find_token(sign, "r", 0), 1, GCRYMPI_FMT_USG);
    s_mpi = gcry_sexp_nth_mpi(gcry_sexp_find_token(sign, "s", 0), 1, GCRYMPI_FMT_USG);

    memset(r_buf, 0, MAXLINE);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, r_buf, sizeof(r_buf), &nwritten, r_mpi);
    if (err) {
        fprintf(stderr, "failed to stringify r-mpi\n");
        return -1;
    }
    if(send(cli_sockfd, r_buf, nwritten, 0) == -1) {
        printf("Send signed message failed\n");
        return -1;
    }
    memset(s_buf, 0, MAXLINE);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, s_buf, sizeof(s_buf), &nwritten, s_mpi);
    if (err) {
        fprintf(stderr, "failed to stringify s-mpi\n");
        return -1;
    }
    if(send(cli_sockfd, s_buf, nwritten, 0) == -1) {
        printf("Send signed message failed\n");
        return -1;
    }
    printf("Successfully sent signed message to client\n");

    /* Release contexts. */
    gcry_mpi_release(r_mpi);
    gcry_mpi_release(s_mpi);
    gcry_sexp_release(plain);
    gcry_sexp_release(sign);
    gcry_sexp_release(skey);

    return 1;
}

int main(int argc, char *argv[]) {
    struct sockaddr_in addr = {0};
    struct sockaddr cli_addr = {0};
    int sockfd, cli_sockfd;
    socklen_t clilen = sizeof(cli_addr);
    char buf[MAXLINE];

    init_gcrypt();
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
    }

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        return 1;
    }

    printf("Server start\n");

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORTNUM);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if(bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        printf("bind error\n");
        return 1;
    }
    
    if(listen(sockfd, 5) == -1) {
       printf("listen error\n");
       return 1;
    }
    
    while(1) {
        cli_sockfd = accept(sockfd, &cli_addr, &clilen);
        if(cli_sockfd < 0) {
            exit(0);
        }

        memset(buf, 0, MAXLINE);
        if(recv(cli_sockfd, buf, MAXLINE, 0) == -1) {
            fprintf(stderr, "Receive client request failed\n");
            close(cli_sockfd);
            continue;
        }
        printf("Client request received: %s\n", buf);

        signMessage(cli_sockfd, buf);

        close(cli_sockfd);
    }
    return 0;
}

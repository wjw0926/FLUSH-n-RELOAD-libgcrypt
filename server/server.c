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

int decryptString(int sockfd, unsigned char *buf) {
    unsigned char sock_buf[MAXLINE];
    FILE* f;
    void* rsa_buf;
    gcry_error_t err;
    gcry_mpi_t plain_mpi;
    gcry_sexp_t plain;
    gcry_sexp_t cipher;
    gcry_sexp_t keypair;
    gcry_sexp_t skey;

    /* Load private-key */
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
    skey = gcry_sexp_find_token(keypair, "private-key", 0);
    gcry_sexp_release(keypair);

    /* Note: %s format will be cut at the \0 position */
    err = gcry_sexp_build(&cipher, NULL, "(enc-val (flags) (rsa (a %b)))", 256, buf);
    if(err) {
        fprintf(stderr, "failed to create a sexp from the message\n");
        return -1;
    }

    /* Decrypt the CIPHER using the private key SKEY and store the result as
       a newly created S-expression at PLAIN. */
    err = gcry_pk_decrypt(&plain, cipher, skey);
    if (err) {
        fprintf(stderr, "gcrypt decryption failed: %s\n", gcry_strsource(err));
        return -1;
    }

    plain_mpi = gcry_sexp_nth_mpi(plain, 1, GCRYMPI_FMT_USG);

    memset(sock_buf, 0, MAXLINE);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) &sock_buf, sizeof(sock_buf), NULL, plain_mpi);
    if (err) {
        fprintf(stderr, "failed to stringify plain mpi\n");
        return -1;
    }

    if(send(sockfd, (unsigned char *) sock_buf, MAXLINE, 0) == -1) {
        printf("Send decrypted message failed\n");
        return -1;
    }
    printf("Successfully sent decrypted message to client: %s\n", (char *) sock_buf);

    /* Release contexts. */
    gcry_mpi_release(plain_mpi);
    gcry_sexp_release(plain);
    gcry_sexp_release(cipher);
    gcry_sexp_release(skey);

    return 1;
}

int processRequest(int sockfd) {
    unsigned char buf[MAXLINE];
    int ret = 1;

    while(1)
    {
        memset(buf, 0, sizeof(buf));
        if(recv(sockfd, buf, MAXLINE, 0) == -1) {
            fprintf(stderr, "Recv client request failed\n");
            return -1;
        }
        printf("Client request received\n");

        ret = decryptString(sockfd, buf);
        break;
    }
    if (ret == -1) {
        fprintf(stderr, "Client request failed\n");
        exit(0);
    }
    return ret;
}

int main(int argc, char *argv[]) {
    struct sockaddr_in addr = {0};
    struct sockaddr cli_addr = {0};
    int sockfd, cli_sockfd;
    socklen_t clilen = sizeof(cli_addr);

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
       processRequest(cli_sockfd);
       close(cli_sockfd);
    }
    return 0;
}

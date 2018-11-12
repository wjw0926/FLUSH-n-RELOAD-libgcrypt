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

int decryptString(int sockfd, unsigned char *buf, gcry_sexp_t skey) {
    gcry_error_t err;
    gcry_mpi_t plain_mpi;
    gcry_mpi_t cipher_mpi;
    gcry_sexp_t plain;
    gcry_sexp_t cipher;

    /*size_t nscanned = 0;*/
    /*err = gcry_mpi_scan(&cipher_mpi, GCRYMPI_FMT_USG, buf, 256, &nscanned);*/
    /*if(err) {*/
        /*fprintf(stderr, "failed to create a mpi from the message\n");*/
        /*exit(1);*/
    /*}*/
    /*printf("nscanned: %d\n", nscanned);*/
    /*printf("Cipher MPI: \n");*/
    /*gcry_mpi_dump(cipher_mpi);*/
    /*printf("\n");*/

    /* Note: %s format will be cut at the \0 position */
    //err = gcry_sexp_build(&cipher, NULL, "(enc-val (flags) (rsa (a %M)))", cipher_mpi);
    err = gcry_sexp_build(&cipher, NULL, "(enc-val (flags) (rsa (a %b)))", 256, buf);
    if(err) {
        fprintf(stderr, "failed to create a sexp from the message\n");
        exit(1);
    }
    gcry_sexp_dump(cipher);

    /* Decrypt the CIPHER using the private key SKEY and store the result as
       a newly created S-expression at PLAIN. */
    printf("B\n");
    err = gcry_pk_decrypt(&plain, cipher, skey);
    printf("A\n");
    if (err) {
        printf("Error case: %d\n", err);
        fprintf(stderr, "gcrypt decryption failed: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
        exit(1);
    }
    printf("Decryption successed\n");
    gcry_sexp_dump(plain);
    printf("BA\n");

    memset(buf, 0, MAXLINE);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) &buf, sizeof(buf), NULL, plain_mpi);
    if (err) {
        fprintf(stderr, "failed to stringify mpi\n");
        exit(1);
    }
    printf("Plain: %s\n", (char*) buf);

    if(send(sockfd, buf, MAXLINE, 0) == -1) {
        printf("Send decrypted message failed\n");
        exit(0);
    }

    /* Release contexts. */
    gcry_mpi_release(cipher_mpi);
    gcry_sexp_release(cipher);
    gcry_sexp_release(plain);
    gcry_mpi_release(plain_mpi);

    return 1;
}

int processRequest(int sockfd, gcry_sexp_t skey) {
    unsigned char buf[MAXLINE];
    int ret = 1;

    while(1)
    {
        memset(buf, 0, sizeof(buf));
        if(recv(sockfd, buf, MAXLINE, 0) == -1) {
            printf("Recv client request failed\n");
            return -1;
        }

        decryptString(sockfd, buf, skey);
        break;
    }
    if (ret == -1) {
        printf("Client request failed\n");
        exit(0);
    }
    return ret;
}

gcry_sexp_t keyGeneration() {
    FILE* f;
    void* rsa_buf;
    gcry_error_t err = 0;
    gcry_sexp_t params;
    gcry_sexp_t keypair;
    gcry_sexp_t skey;

    f = fopen("rsa.sp", "wb");
    if (!f) {
        fprintf(stderr, "fopen() failed\n");
        exit(0);
    }

    err = gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err) {
        fprintf(stderr, "gcrypt: failed to create rsa params\n");
        exit(0);
    }

    err = gcry_pk_genkey(&keypair, params);
    if (err) {
        fprintf(stderr, "gcrypt: failed to create rsa key pair\n");
        exit(0);
    }

    printf("RSA key generation complete\n");

    skey = gcry_sexp_find_token(keypair, "private-key", 0);

    rsa_buf = calloc(1, RSA_KEYPAIR_LEN);
    if (!rsa_buf) {
        fprintf(stderr, "malloc: could not allocate rsa buffer\n");
        exit(0);
    }

    gcry_sexp_sprint(keypair, GCRYSEXP_FMT_CANON, rsa_buf, RSA_KEYPAIR_LEN);

    if (fwrite(rsa_buf, RSA_KEYPAIR_LEN, 1, f) != 1) {
        fprintf(stderr, "fwrite() failed\n");
        exit(0);
    }

    /* Release contexts. */
    gcry_sexp_release(keypair);
    gcry_sexp_release(params);
    gcry_sexp_release(skey);
    free(rsa_buf);
    fclose(f);

    return skey;
}

int main(int argc, char * argv[]) {
    struct sockaddr_in addr = {0};
    struct sockaddr cli_addr = {0};
    int sockfd, cli_sockfd;
    socklen_t clilen = sizeof(cli_addr);
    int pid;
    gcry_sexp_t skey;

    init_gcrypt();
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
    }

    skey = keyGeneration();

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
       pid = fork();
       
       if(pid == 0) {
           processRequest(cli_sockfd, skey);
           close(cli_sockfd);
       }
       else{
           close(cli_sockfd);
       }
    }
    return 0;
}

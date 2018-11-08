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

#define PORTNUM 3800
#define MAXLINE 1024

#define ECHO 1
#define ENCRYPT 2
#define DECRYPT 3

int processRequest(int sockfd);
int echoString(int sockfd, char *str);
int encryptString(int sockfd, char *str);
int decryptString(int sockfd, char *str);

int main(int argc, char * argv[]) {
    struct sockaddr_in addr = {0};
    struct sockaddr cli_addr = {0};
    int sockfd, cli_sockfd;
    socklen_t clilen = sizeof(cli_addr);
    int pid;
    
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
       pid = fork();
       
       if(pid == 0) {
           processRequest(cli_sockfd);
           close(cli_sockfd);
       }
       else{
           close(cli_sockfd);
       }
    }
    return 0;
}

int processRequest(int sockfd) {
    char buf[MAXLINE];
    int command = 0;
    char str[MAXLINE];
    int ret = 1;

    while(1)
    {
        if(recv(sockfd, buf, MAXLINE, 0) == -1) {
               return -1;
        }
        command = atoi(buf);
 
        if(recv(sockfd, buf, MAXLINE, 0) == -1) {
            return -1;
        }
        strncpy(str, buf, MAXLINE);
 
        printf("Received request: %d, %s\n", command, str);
 
        switch(command)
        {
           case ECHO:
               echoString(sockfd, str);
               break;
           case ENCRYPT:
               encryptString(sockfd, str);
               break;
           case DECRYPT:
               decryptString(sockfd, str);
               break;
           default:
               ret = -1;
               break;
        }
        break;
    }
    if (ret == -1) {
        printf("Client request failed\n");
        exit(0);
    }
    return ret;
}

int echoString(int sockfd, char *str) {
    char buf[MAXLINE];

    memset(buf, 0, MAXLINE);
    strncpy(buf, str, MAXLINE);

    if(send(sockfd, buf, MAXLINE, 0) == -1) {
        printf("Send echoString failed\n");
        exit(0);
    }
    return 1;
}

int encryptString(int sockfd, char *str) {
    char buf[MAXLINE];
    gcry_error_t err;
    gcry_mpi_t plain_mpi;
    gcry_mpi_t cipher_mpi;
    gcry_sexp_t plain;
    gcry_sexp_t cipher;
    gcry_sexp_t pkey;

    memset(buf, 0, MAXLINE);
    strncpy(buf, str, MAXLINE);

    err = gcry_mpi_scan(&plain_mpi, GCRYMPI_FMT_USG, buf, strlen((const char *) buf), NULL);
    if(err) {
        fprintf(stderr, "failed to create a mpi from the message");
        exit(1);
    }

    err = gcry_sexp_build(&plain, NULL, "(data (flags raw) (value %m))", plain_mpi);
    if(err) {
        fprintf(stderr, "failed to create a sexp from the message");
        exit(1);
    }

    /* Encrypt the PLAIN using the public key PKEY and store the result as
       a newly created S-expression at CIPHER. */
    err = gcry_pk_encrypt(&cipher, plain, pkey);
    if(err) {
        fprintf(stderr, "gcrypt: encryption failed");
        exit(1);
    }

    cipher_mpi = gcry_sexp_nth_mpi(cipher, 0, GCRYMPI_FMT_USG);
    gcry_mpi_dump(cipher_mpi);

    memset(buf, 0, MAXLINE);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) &buf, sizeof(buf), NULL, cipher_mpi);
    if (err) {
        fprintf(stderr, "failed to stringify mpi");
        exit(1);
    }
    printf("-> %s\n", (char*) buf);

    if(send(sockfd, buf, MAXLINE, 0) == -1) {
        printf("Send encryptString failed\n");
        exit(0);
    }

    /* Release contexts. */
    gcry_mpi_release(plain_mpi);
    gcry_mpi_release(cipher_mpi);
    gcry_sexp_release(plain);
    gcry_sexp_release(cipher);
    gcry_sexp_release(pkey);

    return 1;
}

int decryptString(int sockfd, char *str) {
    char buf[MAXLINE];
    gcry_error_t err;
    gcry_mpi_t plain_mpi;
    gcry_mpi_t cipher_mpi;
    gcry_sexp_t plain;
    gcry_sexp_t cipher;
    gcry_sexp_t skey;

    memset(buf, 0, MAXLINE);
    strncpy(buf, str, MAXLINE);

    /* Decrypt the CIPHER using the private key SKEY and store the result as
       a newly created S-expression at PLAIN. */
    err = gcry_pk_decrypt(&plain, cipher, skey);
    if (err) {
        fprintf(stderr, "gcrypt: decryption failed");
        exit(1);
    }

    if(send(sockfd, buf, MAXLINE, 0) == -1) {
        printf("Send decryptString failed\n");
        exit(0);
    }

    /* Release contexts. */
    gcry_mpi_release(plain_mpi);
    gcry_mpi_release(cipher_mpi);
    gcry_sexp_release(plain);
    gcry_sexp_release(cipher);
    gcry_sexp_release(skey);

    return 1;
}

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

int sendRequest(int sockfd, char *str);

void help(char *progname)
{
    printf("Usage : %s -h -i [ip] -m [msg]\n", progname);
}

int main(int argc, char * argv[]) {
    struct sockaddr_in addr={0};
    int sockfd;
    socklen_t servlen;
    
    int opt;
    int optflag=0;
    char ipaddr[36]={0x00,};
    char str[MAXLINE];
    char buf[MAXLINE];
    
    init_gcrypt();
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
    }

    while((opt = getopt(argc, argv, "hi:m:")) != -1) {
        switch(opt) {
            case 'h':
                help(argv[0]);
                return 1;
            case 'i':
                sprintf(ipaddr, "%s", optarg);
                break;
            case 'm':
                sprintf(str, "%s", optarg);
                optflag = 1;
                break;
            default:
                help(argv[0]);
                return 1;
        }
    }
    
    if(ipaddr[0] == '\0') {
        printf ("ip address not setting\n");
        return 0;
    }
    
    if((str[0] == '\0') && (optflag == 1)) {
        printf ("string error\n");
        return 0;
    }

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
         printf("Socket error\n");
         return 1;
    }
    
    addr.sin_family     = AF_INET;
    addr.sin_port       = htons(PORTNUM);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    servlen = sizeof(addr);
    if(connect(sockfd, (struct sockaddr *)&addr, servlen) == -1) {
        printf("Connect error\n");
        return 0;
    }
    
    while(1)
    {
        if(sendRequest(sockfd, str) == -1) {
            printf("Send message failed\n");
            close(sockfd);
            return -1;
        }

        if(recv(sockfd, buf, MAXLINE, 0) == -1) {
            printf("Recv message failed\n");
            close(sockfd);
            return -1;
        }
        printf("Received: %s\n", buf);
        
        break;
    }
    close(sockfd);
}

int sendRequest(int sockfd, char *str) {
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
    gcry_sexp_t data;

    f = fopen("rsa.sp", "rb");
    if (!f) {
        fprintf(stderr, "fopen() failed\n");
        return -1;
    }

    rsa_buf = calloc(1, RSA_KEYPAIR_LEN);
    if (!rsa_buf) {
        fprintf(stderr, "malloc: could not allocate rsa buffer\n");
        return -1;
    }
    if (fread(rsa_buf, RSA_KEYPAIR_LEN, 1, f) != 1) {
        fprintf(stderr, "fread() failed\n");
        return -1;
    }

    err = gcry_sexp_new(&keypair, rsa_buf, RSA_KEYPAIR_LEN, 0);
    pkey = gcry_sexp_find_token(keypair, "public-key", 0);

    memset(buf, 0, MAXLINE);
    strncpy(buf, str, MAXLINE);

    err = gcry_mpi_scan(&plain_mpi, GCRYMPI_FMT_USG, buf, strlen((const char *) buf), NULL);
    if(err) {
        fprintf(stderr, "failed to create a mpi from the message\n");
        return -1;
    }

    err = gcry_sexp_build(&plain, NULL, "(data (flags raw) (value %m))", plain_mpi);
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
    gcry_sexp_dump(cipher);

    //data = gcry_sexp_car(gcry_sexp_nth(gcry_sexp_car(gcry_sexp_cdr(gcry_sexp_car(cipher))), 1));
    //gcry_sexp_dump(data);
    cipher_mpi = gcry_sexp_nth_mpi(gcry_sexp_car(gcry_sexp_nth(gcry_sexp_car(gcry_sexp_cdr(gcry_sexp_car(cipher))), 1)), 1, GCRYMPI_FMT_USG);
    //cipher_mpi = gcry_sexp_nth_mpi(data, 1, GCRYMPI_FMT_USG);
    printf("Cipher MPI: \n");
    gcry_mpi_dump(cipher_mpi);
    printf("\n");

    memset(buf, 0, MAXLINE);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) &buf, sizeof(buf), NULL, cipher_mpi);
    if(err) {
        fprintf(stderr, "failed to stringify cipher mpi\n");
        return -1;
    }
    //printf("Cipher: %s\n", (char *) buf);

    if(send(sockfd, buf, MAXLINE, 0) == -1) {
        printf("Send encrypted message failed\n");
        return -1;
    }

    /* Release contexts. */
    fclose(f);
    free(rsa_buf);
    gcry_sexp_release(keypair);
    gcry_mpi_release(plain_mpi);
    gcry_sexp_release(plain);
    gcry_sexp_release(pkey);
    gcry_sexp_release(cipher);
    gcry_sexp_release(data);
    gcry_mpi_release(cipher_mpi);

    return 1;
}

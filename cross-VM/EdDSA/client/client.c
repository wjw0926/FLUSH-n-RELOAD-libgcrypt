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

int verifyMessage(int sockfd, char *str, unsigned char *r_buf, unsigned char *s_buf) {
    FILE* f;
    void* ecc_buf;
    gcry_error_t err;
    gcry_mpi_t r_mpi;
    gcry_mpi_t s_mpi;
    gcry_sexp_t plain;
    gcry_sexp_t sign;
    gcry_sexp_t keypair;
    gcry_sexp_t pkey;

    /* Load publid-key */
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
    pkey = gcry_sexp_find_token(keypair, "public-key", 0);
    gcry_sexp_release(keypair);

    /* Client's original message */
    err = gcry_sexp_build(&plain, NULL, "(data (flags eddsa) (hash-algo sha512) (value %s))", str);
    if(err) {
        fprintf(stderr, "failed to create sexp from the mesaage\n");
        return -1;
    }

    /* Received signed message */
    err = gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_USG, r_buf, 32, NULL);
    if(err) {
        fprintf(stderr, "failed to create r-mpi from the message\n");
        return -1;
    }
    err = gcry_mpi_scan(&s_mpi, GCRYMPI_FMT_USG, s_buf, 32, NULL);
    if(err) {
        fprintf(stderr, "failed to create s-mpi from the message\n");
        return -1;
    }
    err = gcry_sexp_build(&sign, NULL, "(sig-val (eddsa (r %M) (s %M)))", r_mpi, s_mpi);
    if(err) {
        fprintf(stderr, "failed to create sexp from the mpi\n");
        return -1;
    }

    /* Verification */
    err = gcry_pk_verify(sign, plain, pkey);
    if(err) {
        fprintf(stderr, "gcrypt verification failed: %s\n", gcry_strsource(err));
        return -1;
    }
    else {
        printf("Verification success!\n");
    }

    /* Release contexts. */
    gcry_mpi_release(r_mpi);
    gcry_mpi_release(s_mpi);
    gcry_sexp_release(plain);
    gcry_sexp_release(sign);
    gcry_sexp_release(pkey);

    return 1;
}

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
    char r_buf[MAXLINE];
    char s_buf[MAXLINE];

    /* Initialize libgcrypt */
    init_gcrypt();
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
    }

    /* Argument parsing */
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

    /* Socket communication  */
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
         printf("Socket error\n");
         return 0;
    }

    addr.sin_family     = AF_INET;
    addr.sin_port       = htons(PORTNUM);
    addr.sin_addr.s_addr = inet_addr(ipaddr);
    
    servlen = sizeof(addr);
    if(connect(sockfd, (struct sockaddr *)&addr, servlen) == -1) {
        printf("Connect error\n");
        return 0;
    }
    
    while(1)
    {
        if(send(sockfd, str, MAXLINE, 0) == -1) {
            printf("Send message failed\n");
            close(sockfd);
            return -1;
        }

        if(recv(sockfd, r_buf, 32, 0) == -1) {
            printf("Receive signed message (r) failed\n");
            close(sockfd);
            return -1;
        }
        if(recv(sockfd, s_buf, 32, 0) == -1) {
            printf("Receive signed message (s) failed\n");
            close(sockfd);
            return -1;
        }
        verifyMessage(sockfd, str, (unsigned char *) r_buf, (unsigned char *) s_buf); 

        break;
    }
    close(sockfd);

    return 1;
}

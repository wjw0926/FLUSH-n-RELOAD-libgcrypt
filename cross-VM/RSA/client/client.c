#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "common.h"

int sendRequest(int sockfd);

void help(char *progname)
{
    printf("Usage : %s -h -i [ip]\n", progname);
}

int main(int argc, char * argv[]) {
    struct sockaddr_in addr={0};
    int sockfd;
    socklen_t servlen;
    int opt;
    char ipaddr[36]={0x00,};
    char buf[MAXLINE];

    /* Argument parsing */
    while((opt = getopt(argc, argv, "hi:")) != -1) {
        switch(opt) {
            case 'h':
                help(argv[0]);
                return 1;
            case 'i':
                sprintf(ipaddr, "%s", optarg);
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
        if(sendRequest(sockfd) == -1) {
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

    return 1;
}

int sendRequest(int sockfd) {
    char *buf;
    FILE* f;

    /* Load cipher text */
    f = fopen("cipher.txt", "rb");
    if(!f) {
        fprintf(stderr, "fopen() failed\n");
        return -1;
    }

    buf = (char *) malloc(sizeof(char) * MAXLINE);
    if(!buf) {
        fprintf(stderr, "malloc: could not allocate cipher buffer\n");
        return -1;
    }

    if(fread(buf, MAXLINE, 1, f) != 1) {
        fprintf(stderr, "fread() failed\n");
        return -1;
    }
    fclose(f);

    if(send(sockfd, (unsigned char *) buf, MAXLINE, 0) == -1) {
        printf("Send encrypted message failed\n");
        return -1;
    }
    free(buf);

    return 1;
}

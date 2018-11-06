#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORTNUM 3800
#define MAXLINE 1024

#define ECHO 1
#define ENCRYPT 2
#define DECRYPT 3

int sendRequest(int sockfd, char *str, int command_type);

void help(char *progname)
{
    printf("Usage : %s -h -i [ip] -c [echo string] -e [encrypt string] -d [decrypt string]\n", progname);
}

int main(int argc, char * argv[]) {
    struct sockaddr_in addr={0};
    int sockfd;
    socklen_t servlen;
    
    int command_type=0;
    int opt;
    int optflag=0;
    char ipaddr[36]={0x00,};
    char str[MAXLINE];
    char buf[MAXLINE];
    
    while((opt = getopt(argc, argv, "hi:c:e:d:")) != -1) {
        switch(opt) {
            case 'h':
                help(argv[0]);
                return 1;
            case 'i':
                sprintf(ipaddr, "%s", optarg);
                break;
            case 'c':
                command_type = ECHO;
                sprintf(str, "%s", optarg);
                optflag = 1;
                break;
            case 'e':
                command_type = ENCRYPT;
                sprintf(str, "%s", optarg);
                optflag = 1;
                break;
            case 'd':
                command_type = DECRYPT;
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
        sendRequest(sockfd, str, command_type);

        if(recv(sockfd, buf, MAXLINE, 0) == -1) {
            printf("Recv string failed\n");
            close(sockfd);
            return -1;
        }
        printf("Received: %s\n", buf);
        
        break;
    }
    close(sockfd);
}

int sendRequest(int sockfd, char *str, int command_type)
{
    int sendn;
    char buf[MAXLINE];

    sprintf(buf, "%d", command_type);
    if(send(sockfd, buf, MAXLINE, 0) == -1) {
        printf("Send command failed\n");
        close(sockfd);
        return -1;
    }

    sprintf(buf, "%s", str);
    if(send(sockfd, buf, MAXLINE, 0) == -1) {
        printf("Send string failed\n");
        close(sockfd);
        return -1;
    }

    return 1;
}

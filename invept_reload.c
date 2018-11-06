#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long threshold = 1000ul;

unsigned long probe(char *addr) {
    volatile unsigned long time;

    __asm__ __volatile__ (
        " mfence                \n"
        " lfence                \n"
        " rdtsc                 \n"
        " lfence                \n"
        " movl %%eax, %%esi     \n"
        " movl (%1), %%eax      \n"
        " lfence                \n"
        " rdtsc                 \n"
        " subl %%esi, %%eax     \n"
        " invept 0(%1)         \n"
        : "=a" (time)
        : "c" (addr)
        : "%esi", "%edx");
    
    return time;
}

int main(int argc, char* argv[]) {
    int opt;

    char* addr = (char *) malloc(sizeof(char) * 64);
    
    while ((opt = getopt(argc, argv, "a:")) != -1) {
        switch (opt) {
            case 'a':
                memset(addr, 0, strlen(addr));
                strncpy(addr, optarg, strlen(optarg));
                break;
            case '?':
                fprintf(stderr, "Usage: %s [-a] [address...]\n", argv[0]);
                return 0;
            default:
                fprintf(stderr, "Usage: %s [-a] [address...]\n", argv[0]);
                return 0;
        }
    }
    printf("Address of the addr pointer: %p\n", addr);
    printf("Value of the addr pointer: %s\n", addr);
    printf("Time: %lu\n", probe(addr));

    free(addr);
    return 0;
}

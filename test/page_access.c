#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long threshold = 100ul;

/* Access the data at a memory address and flush */
void access_flush(char *addr) {

    __asm__ __volatile__ (
        " mfence                \n"
        " lfence                \n"
        /* Load the 4 bytes from the memory address in ECX into EAX */
        " movl (%0), %%eax      \n"
        " lfence                \n"
        " clflush 0(%0)         \n"
        :
        : "c" (addr)
        : );
}

/* Measure the time to read the data at a memory address */
unsigned long reload(char *addr) {
    volatile unsigned long time;

    __asm__ __volatile__ (
        " mfence                \n"
        " lfence                \n"
        " rdtsc                 \n"
        " lfence                \n"
        " movl %%eax, %%esi     \n"
        /* Load the 4 bytes from the memory address in ECX into EAX */
        " movl (%1), %%eax      \n"
        " lfence                \n"
        " rdtsc                 \n"
        " subl %%esi, %%eax     \n"
        : "=a" (time)
        : "c" (addr)
        : "%esi", "%edx");

    printf("Address of the addr pointer: %p\n", addr);
    return time;
}

int main(int argc, char *argv[]) {

    int i;
    unsigned long time;
    int NUM = 1024;

    char **strs = (char **) malloc(NUM * sizeof(char*));
    for(i = 0; i < NUM; i++) {
        /*Allocate 4KB(page unit stride) for each entry: 4KB * 1024 = 4GB footprint */
        strs[i] = malloc(4096 * sizeof(char));
    }

    for(i = 0; i < NUM; i++) {
        sprintf(strs[i], "%d", i*1024);
    }

    /* Flush */
    for(i = 0; i < NUM; i++) {
        access_flush(strs[i]);
    }
 
    /* Wait */
    usleep(1000);

    /* Reload*/
    for(i = 0; i < NUM; i++) {
        time = reload(strs[i]);
        if(time > threshold) {
            printf("Reload time: %lu\n", time);
        }
    }

    for(i = 0; i < NUM; i++) {
        free(strs[i]);
    }
    free(strs);

    return 0;
}

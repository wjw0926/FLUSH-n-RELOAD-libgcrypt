#include "asm.h"

void busy_wait(int cycle) {
    volatile long i;

    for(i = 0; i < cycle; i++) {
        ;
    }
}

/* Access the data at a memory address */
void access_data(char *addr) {

    __asm__ __volatile__ (
        " mfence                \n"
        " lfence                \n"
        " movl (%0), %%eax      \n"
        :
        : "c" (addr)
        : );
}

/* Flush the data at a memory address */
void flush_data(char *addr) {

    __asm__ __volatile__ (
        " mfence                \n"
        " lfence                \n"
        " clflush 0(%0)         \n"
        :
        : "c" (addr)
        : );
}

/* Measure the time to reload the data at a memory address */
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
        " clflush 0(%1)         \n"
        : "=a" (time)
        : "c" (addr)
        : "%esi", "%edx");

    return time;
}

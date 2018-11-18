#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

unsigned long threshold = 100ul;

#define INVEPT_OPCODE   ".byte 0x66,0x0f,0x38,0x80\n"   /* m128,r64/32 */
#define MODRM_EAX_08    ".byte 0x08\n"                  /* ECX, [EAX] */

#define INVEPT_SINGLE_CONTEXT   1
#define INVEPT_ALL_CONTEXT      2

/* Access the data at a memory address */
void access_data(char *addr) {

    __asm__ __volatile__ (
        " mfence                \n"
        " lfence                \n"
        /* Load the 4 bytes from the memory address in ECX into EAX */
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

/* INVEPT: Invalidate translations derived from EPT */
void invept_data(char *addr) {

    int type;
    uint64_t eptp = 0;
    uint64_t gpa = 0;

    /*char descriptor[128];*/
    /*//TODO: addr should be relaced with eptp*/
    /*snprintf(descriptor, sizeof(descriptor), "0000000000000000%s", addr);*/
    /*printf("%s\n", descriptor);*/

    struct {
        uint64_t eptp, gpa;
    } operand = {eptp, gpa};

    /*if ( (type == INVEPT_SINGLE_CONTEXT) &&*/
         /*!cpu_has_vmx_ept_invept_single_context )*/
        type = INVEPT_ALL_CONTEXT;

    asm volatile ( INVEPT_OPCODE
                   MODRM_EAX_08
                   /* CF==1 or ZF==1 --> crash (ud2) */
                   "ja 1f ; ud2 ; 1:\n"
                   :
                   : "a" (&operand), "c" (type)
                   : "memory" );

    /*__asm__ __volatile__ (*/
        /*" mfence                \n"*/
        /*" lfence                \n"*/
        /*// format: invept m128(16 bytes zeros and EPTP), r64*/
        /*" invept %0 %%rcx         \n"*/
        /*" setna al               \n"*/
        /*:*/
        /*: "d" (descriptor)*/
        /*: "memory");*/
}

/* Measure the time to reload the data at a memory address */
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

    //printf("Address of the addr pointer: %p\n", addr);
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

    /* Access or Flush */
    for(i = 0; i < NUM; i++) {
        access_data(strs[i]);
        //flush_data(strs[i]);
        //invept_data(strs[i]);
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

#include <stdio.h>

void busy_wait(int cycle);

/* Access the data at a memory address */
void access_data(char *addr);

/* Flush the data at a memory address */
void flush_data(char *addr);

/* Measure the time to reload the data at a memory address */
unsigned long reload(char *addr);

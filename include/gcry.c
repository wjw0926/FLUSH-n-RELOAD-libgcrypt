#include "gcry.h"

void init_gcrypt_secure() {
    /* Version check should be the very first call because it
       makes sure that important subsystems are initialized. */
    if (!gcry_check_version (GCRYPT_VERSION)) {
      fputs ("libgcrypt version mismatch\n", stderr);
      exit (2);
    }

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been initialized.  */

    /* Allocate a pool of 16k secure memory.  This makes the secure memory
       available and also drops privileges where needed.  Note that by
       using functions like gcry_xmalloc_secure and gcry_mpi_snew Libgcrypt
       may expand the secure memory pool with memory which lacks the
       property of not being swapped out to disk.   */
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

void init_gcrypt() {
    /* Version check should be the very first call because it
       makes sure that important subsystems are initialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        fputs ("libgcrypt version mismatch\n", stderr);
        exit (2);
    }

    /* Disable secure memory.  */
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

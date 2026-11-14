/* Print libgcrypt's version and its active hardware-feature list
 * (after /etc/gcrypt/hwf.deny is applied). Diagnostic only. */
#include <gcrypt.h>
#include <stdio.h>

int main(void)
{
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_PRINT_CONFIG, stdout);
    return 0;
}

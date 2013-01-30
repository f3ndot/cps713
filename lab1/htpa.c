#define DEBUG 1
#define DEBUG_LEVEL 3

#include <stdio.h>
#include "htpa.h"

int main(int argc, char const *argv[])
{

  char plaintext[] = "Hello and Goodbye";
  debug_print(1, "Plaintext: %s\n", plaintext);

  debug_print(3, "HTPA Block Length: %i\n", BLOCK_LEN);
  debug_print(3, "HTPA Key Length: %i\n", KEY_LEN);
  debug_print(3, "HTPA Round Key Length: %i\n", ROUND_KEY_LEN);
  return 0;
}
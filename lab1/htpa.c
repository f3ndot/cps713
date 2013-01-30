#define DEBUG 1

#include <stdio.h>
#include "htpa.h"

int main(int argc, char const *argv[])
{
  debug_print("Block Size: %i\n", BLOCK_LEN);
  debug_print("Key Size: %i\n", KEY_LEN);
  return 0;
}
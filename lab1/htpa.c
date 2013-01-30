#define DEBUG 1
#define DEBUG_LEVEL 2

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htpa.h"

int main(int argc, char const *argv[]) {

  debug_print(3, "HTPA Block Length: %i\n", BLOCK_LEN);
  debug_print(3, "HTPA Key Length: %i\n", KEY_LEN);
  debug_print(3, "HTPA Round Key Length: %i\n", ROUND_KEY_LEN);

  char plaintext[] = "Hello and Goodbye";
  debug_print(1, "Plaintext: \"%s\" (%i bits)\n", plaintext, calc_bits(plaintext));

  char **blocks_array = split_into_blocks(plaintext);

  // int blocks_len = calc_blocks_for_plaintext(plaintext);

  return 0;
}

int calc_bits(char *str) {
  return (int) strlen(str) * CHAR_BIT;
}

int calc_blocks_for_plaintext(char *str) {
  int blocks = 0;
  for (int i = 0; i < strlen(str); ++i) {
    if ((i * CHAR_BIT) % BLOCK_LEN == 0) {
      blocks++;
    }
  }
  debug_print(1, "Number of Blocks: %i (%i bits)\n", blocks, blocks * BLOCK_LEN);
  return blocks;
}

char** split_into_blocks(char *str) {
  int block_num = 0;
  int orig_str_len = strlen(str);
  char block_str[(BLOCK_LEN / CHAR_BIT) + 1]; // add one more for the null-byte

  // making space for the array of strings
  char **blocks_array = (char **) malloc(calc_blocks_for_plaintext(str) * sizeof(char *));

  for (int i = 0; i < orig_str_len; ++i) {
    if ((i * CHAR_BIT) % BLOCK_LEN == 0) {
      ++block_num;

      if (calc_bits(str) < BLOCK_LEN) {
        debug_print(1, "Block %i: Padding final block \"%s\" (%i bits)\n", block_num, str, calc_bits(str));
        str = pad_block(str);
      }

      strncpy(block_str, str, (BLOCK_LEN / CHAR_BIT));
      block_str[(BLOCK_LEN / CHAR_BIT)] = '\0'; // add the nullbyte
      debug_print(1, "Block %i: \"%s\" (%i bits)\n", block_num, block_str, calc_bits(block_str));

      str = str + (BLOCK_LEN / CHAR_BIT);
      debug_print(2, "Block %i: Moved string pointer to \"%s\"\n", block_num, str);

      blocks_array[block_num] = (char *) malloc(strlen(block_str));
      debug_print(2, "Block %i: Copied \"%s\" to blocks array\n", block_num, block_str);

    }
  }

  return blocks_array;
}

char* pad_block(char *str) {
  char padded_str[(BLOCK_LEN / CHAR_BIT) + 1]; // allow space for null-byte???

  if (calc_bits(str) == BLOCK_LEN) {
    debug_print(1, "Padding not required! Returning string block unpadded%s", "\n");
  } else {
    int padlen = BLOCK_LEN - (strlen(str) * CHAR_BIT);
    debug_print(2, "Need to pad block with %i bits\n", padlen);

    strcat(padded_str, str);
    for (int i = 0; i < (padlen/CHAR_BIT); ++i) {
      strcat(padded_str, " "); // takes care of null-bytes for me (removes dest's and add's src's)
    }
  }

  return padded_str;
}
#define DEBUG 1
#define DEBUG_LEVEL 3

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htpa.h"


int main(int argc, char const *argv[]) {

  debug_print(3, "HTPA Block Length: %i\n", BLOCK_LEN);
  debug_print(3, "HTPA Key Length: %i\n", KEY_LEN);
  debug_print(3, "HTPA Round Key Length: %i\n", ROUND_KEY_LEN);

  char string[] = "AAA";
  // char string[] = {0x41, 0x41, 0x41, 0x41};
  htpa_bytes plaintext;

  plaintext.bytes = (unsigned char *) string;
  plaintext.len = strlen(string);

  char * plaintext_hex = get_bytes_hex(&plaintext);
  char * plaintext_str = get_bytes_str(&plaintext);

  printf("Plaintext ( HEX ): \"%s\" (%i bits)\n", plaintext_hex, calc_bits(&plaintext));
  printf("Plaintext (ASCII): \"%s\" (%i bits)\n", plaintext_str, calc_bits(&plaintext));
  // char **blocks_array = split_into_blocks(plaintext);


  free(plaintext_hex);
  plaintext_hex = NULL;
  free(plaintext_str);
  plaintext_str = NULL;
  exit(EXIT_SUCCESS);
}

char * get_bytes_hex(htpa_bytes * bytes) {
  int strsize = bytes->len * 3 - 1 + 1;
  char * str = (char *) malloc(strsize); // -1 for missing space and +1 for str nullbyte
  for (int i = 0; i < strsize; ++i) { str[i] = '\0'; } // initialize string space of null

  for (int i = 0; i < bytes->len; ++i) {
    if (i > 0) sprintf(str, "%s ", str);
    sprintf(str, "%s%02X", str, bytes->bytes[i]);
  }

  return str;
}
char * get_bytes_str(htpa_bytes * bytes) {
  int strsize = bytes->len + 1;
  char * str = (char *) malloc(strsize); // -1 for missing space and +1 for str nullbyte
  for (int i = 0; i < strsize; ++i) { str[i] = '\0'; } // initialize string space of null

  for (int i = 0; i < bytes->len; ++i) {
    sprintf(str, "%s%c", str, (char) bytes->bytes[i]);
  }

  return str;
}

int calc_bits(htpa_bytes * bytes) {
  return bytes->len * CHAR_BIT;
}

int calc_blocks_for_plaintext(char *str) {
  int blocks = 0;
  for (int i = 0; i < strlen(str); ++i) {
    if ((i * CHAR_BIT) % BLOCK_LEN == 0) {
      blocks++;
    }
  }
  debug_print(1, "Number of blocks: %i (%i bits)\n", blocks, blocks * BLOCK_LEN);
  return blocks;
}

// char** split_into_blocks(char *str) {
//   int block_num = 0;
//   int orig_str_len = strlen(str);
//   char block_str[(BLOCK_LEN / CHAR_BIT) + 1]; // add one more for the null-byte

//   // making space for the array of strings
//   char **blocks_array = (char **) malloc(calc_blocks_for_plaintext(str) * sizeof(char *));

//   for (int i = 0; i < orig_str_len; ++i) {
//     if ((i * CHAR_BIT) % BLOCK_LEN == 0) {
//       ++block_num;

//       if (calc_bits(str) < BLOCK_LEN) {
//         debug_print(1, "Block %i: Padding final block \"%s\" (%i bits)\n", block_num, str, calc_bits(str));
//         strncpy(block_str, pad_block(str), (BLOCK_LEN / CHAR_BIT));
//       } else {
//         strncpy(block_str, str, (BLOCK_LEN / CHAR_BIT));
//         // block_str[(BLOCK_LEN / CHAR_BIT)] = '\0'; // add the nullbyte
//       }
//       debug_print(1, "Block %i: \"%s\" (%i bits)\n", block_num, block_str, calc_bits(block_str));

//       str = str + (BLOCK_LEN / CHAR_BIT);
//       debug_print(2, "Block %i: Moved string pointer to \"%s\"\n", block_num, str);

//       blocks_array[block_num] = (char *) malloc(strlen(block_str));
//       debug_print(2, "Block %i: Copied \"%s\" to blocks array\n", block_num, block_str);

//     }
//   }

//   return blocks_array;
// }

// char* pad_block(char *str) {
//   char * padded_str = (char *) malloc((BLOCK_LEN / CHAR_BIT) + 1); // allow space for null-byte???

//   if (calc_bits(str) == BLOCK_LEN) {
//     debug_print(1, "Padding not required! Returning string block unpadded%s", "\n");
//   } else {
//     int padlen = BLOCK_LEN - (strlen(str) * CHAR_BIT);
//     debug_print(2, "Need to pad block with %i bits\n", padlen);

//     strcat(padded_str, str);
//     for (int i = 0; i < (padlen/CHAR_BIT); ++i) {
//       strcat(padded_str, " "); // takes care of null-bytes for me (removes dest's and add's src's)
//     }
//   }

//   // TODO: ask Geordie on how to deal with returning of local vars
//   return padded_str;
// }
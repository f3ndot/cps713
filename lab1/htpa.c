#define DEBUG 1
#define DEBUG_LEVEL 4

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htpa.h"


int main(int argc, char const *argv[]) {

  debug_print(3, "HTPA Block Length: %i\n", BLOCK_LEN);
  debug_print(3, "HTPA Key Length: %i\n", KEY_LEN);
  debug_print(3, "HTPA Round Key Length: %i\n", ROUND_KEY_LEN);

  char key_str[] = "AAAAAAAAA";
  htpa_bytes key;
  key.bytes = (unsigned char *) key_str;
  key.len = strlen(key_str);

  printf("Key "); fprint_bytes_hex(stdout, &key);
  printf("Key "); fprint_bytes_str(stdout, &key);

  char plaintext_str[] = "Hello and goodbye, my friend.";
  // char plaintext_str[] = "AAA";
  // char plaintext_str[] = {0x41, 0x41, 0x41, 0x41};
  htpa_bytes plaintext;

  plaintext.bytes = (unsigned char *) plaintext_str;
  plaintext.len = strlen(plaintext_str);

  printf("Plaintext "); fprint_bytes_hex(stdout, &plaintext);
  printf("Plaintext "); fprint_bytes_str(stdout, &plaintext);

  debug_print(1, "Splitting plaintext into blocks%s", "\n");
  htpa_block **blocks_array = split_into_blocks(&plaintext);
  free_blocks_array(blocks_array);

  exit(EXIT_SUCCESS);
}

void fprint_bytes_hex(FILE *stream, htpa_bytes * bytes_ptr) {
  char * bytes_hex_str = get_bytes_hex(bytes_ptr);
  fprintf(stream, "( HEX ): \"%s\" (%i bits)\n", bytes_hex_str, calc_bits(bytes_ptr));
  free(bytes_hex_str);
  bytes_hex_str = NULL;
}

void fprint_bytes_str(FILE *stream, htpa_bytes * bytes_ptr) {
  char * bytes_str = get_bytes_str(bytes_ptr);
  fprintf(stream, "(ASCII): \"%s\" (%i bits)\n", bytes_str, calc_bits(bytes_ptr));
  free(bytes_str);
  bytes_str = NULL;
}

char * get_bytes_hex(htpa_bytes * bytes_ptr) {
  int strsize = bytes_ptr->len * 3 - 1 + 1;
  char * str = (char *) malloc(strsize); // -1 for missing space and +1 for str nullbyte
  for (int i = 0; i < strsize; ++i) { str[i] = '\0'; } // initialize string space of null

  for (int i = 0; i < bytes_ptr->len; ++i) {
    if (i > 0) sprintf(str, "%s ", str);
    sprintf(str, "%s%02X", str, bytes_ptr->bytes[i]);
  }

  return str;
}
char * get_bytes_str(htpa_bytes * bytes_ptr) {
  int strsize = bytes_ptr->len + 1;
  char * str = (char *) malloc(strsize); // -1 for missing space and +1 for str nullbyte
  for (int i = 0; i < strsize; ++i) { str[i] = '\0'; } // initialize string space of null

  for (int i = 0; i < bytes_ptr->len; ++i) {
    sprintf(str, "%s%c", str, (char) bytes_ptr->bytes[i]);
  }

  return str;
}

int calc_bits(htpa_bytes * bytes_ptr) {
  return bytes_ptr->len * CHAR_BIT;
}

int calc_blocks_for_bytes(htpa_bytes * bytes_ptr) {
  int blocks = 0;
  for (int i = 0; i < bytes_ptr->len; ++i) {
    if ((i * CHAR_BIT) % BLOCK_LEN == 0) {
      blocks++;
    }
  }
  debug_print(1, "Number of blocks: %i (%i bits)\n", blocks, blocks * BLOCK_LEN);
  return blocks;
}

htpa_block ** split_into_blocks(htpa_bytes * bytes_ptr) {
  int blocks_total_num = calc_blocks_for_bytes(bytes_ptr);
  int block_num = 0;
  htpa_bytes * bytes_ptr_index = bytes_ptr; // so we can traverse original byte stream without breaking original pointer

  // making space for the array of pointers
  htpa_block **blocks_ptr_array;
  // blocks_ptr_array = (htpa_block **) malloc(sizeof(htpa_block *) * blocks_total_num);

  // making space for each individual pointer
  // for(int i = 0; i < blocks_total_num; i++) {
  //    blocks_ptr_array[i] = (htpa_block *) malloc(sizeof(htpa_block));
  //    blocks_ptr_array[i]->data = (htpa_bytes *) malloc(sizeof(htpa_bytes)); // make space for a byte pointer
  //    blocks_ptr_array[i]->data->len = (BLOCK_LEN / CHAR_BIT);
  // }

  // iterate through the bytes_ptr's data and break it into blocks
  for (int i = 0; i < bytes_ptr->len; ++i) {
    if ((i * CHAR_BIT) % BLOCK_LEN == 0) {
      ++block_num;
      // blocks_ptr_array[i]->number = ++block_num;

      // memcpy(blocks_ptr_array[i]->data->bytes, bytes_ptr_index, (BLOCK_LEN / CHAR_BIT));
      debug_print(2, "Block %i of %i: \n", block_num, blocks_total_num);
    }
  }

  return blocks_ptr_array;
}

void free_blocks_array(htpa_block ** array_ptr) {
  // TODO
}

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
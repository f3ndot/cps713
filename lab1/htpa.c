#define DEBUG 1
#define DEBUG_LEVEL 4

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htpa.h"


int main(int argc, char const *argv[]) {

  debug_print(3, "HTPA Block Length:       %i bytes (%i bits)\n", BLOCK_BYTE_LEN, BLOCK_LEN);
  debug_print(3, "HTPA Block-Half Length:  %i bytes (%i bits)\n", BLOCK_BYTE_HALF_LEN, BLOCK_HALF_LEN);
  debug_print(3, "HTPA Key Length:         %i bytes (%i bits)\n", KEY_BYTE_LEN, KEY_LEN);
  debug_print(3, "HTPA Round Key Length:   %i bytes (%i bits)\n", ROUND_BYTE_KEY_LEN, ROUND_KEY_LEN);

  char key_str[] = "AAAAAAAAA";
  htpa_bytes key;
  key.bytes = (unsigned char *) key_str;
  key.len = strlen(key_str);
  htpa_bytes *key_ptr = &key;

  printf("Key "); fprint_bytes_hex(stdout, key_ptr);
  printf("Key "); fprint_bytes_str(stdout, key_ptr);

  // char plaintext_str[] = "Hello and goodbye, my friend. J! Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur convallis pulvinar nisl vel tincidunt. Ut velit erat, semper at dapibus at, sollicitudin sit amet sem. Cras fringilla arcu augue. Etiam ipsum leo, sagittis aliquet commodo vitae, rutrum sit amet magna. Nunc eget lectus nunc, at varius augue. Nam sodales condimentum libero non imperdiet. Nullam in tellus aliquet libero aliquam venenatis. Praesent imperdiet placerat mauris, suscipit vestibulum massa fringilla et. Fusce at sapien egestas turpis porttitor lobortis. Sed fermentum sagittis tortor quis blandit. Maecenas sed diam quam. Aliquam nisi massa, vestibulum eu fringilla sed, consectetur elementum eros. Ut gravida lectus a eros vestibulum at vestibulum erat molestie.";
  // char plaintext_str[] = "Hello and goodbye, my friend. J!";
  char plaintext_str[] = "Hello and goodbye, my friend.";
  // char plaintext_str[] = "AAA";
  // char plaintext_str[] = {0x41, 0x41, 0x41, 0x41};
  htpa_bytes plaintext;

  plaintext.bytes = (unsigned char *) plaintext_str;
  plaintext.len = strlen(plaintext_str);
  // plaintext.len = 4;
  htpa_bytes *plaintext_ptr = &plaintext;

  printf("Plaintext "); fprint_bytes_hex(stdout, plaintext_ptr);
  printf("Plaintext "); fprint_bytes_str(stdout, plaintext_ptr);

  debug_print(1, "Splitting plaintext into blocks%s", "\n");
  htpa_blocks_array *plaintext_blocks = split_into_blocks(plaintext_ptr);



  free_blocks_array(plaintext_blocks);
  exit(EXIT_SUCCESS);
}

void printf_blocks_array(htpa_blocks_array * array_ptr) {
  for (int i = 0; i < array_ptr->size; ++i)
  {
    printf("Block %i: ", i+1); fprint_bytes_str(stdout, array_ptr->blocks[i]);
    printf("Block %i: ", i+1); fprint_bytes_hex(stdout, array_ptr->blocks[i]);
  }
}

void fprint_bytes_hex(FILE *stream, htpa_bytes * bytes_ptr) {
  char * bytes_hex_str = get_bytes_hex(bytes_ptr);
  fprintf(stream, "( HEX ): \"%s\" (%i bytes, %i bits)\n", bytes_hex_str, bytes_ptr->len, calc_bits(bytes_ptr));
  free(bytes_hex_str);
  bytes_hex_str = NULL;
}

void fprint_bytes_str(FILE *stream, htpa_bytes * bytes_ptr) {
  char * bytes_str = get_bytes_str(bytes_ptr);
  fprintf(stream, "(ASCII): \"%s\" (%i bytes, %i bits)\n", bytes_str, bytes_ptr->len, calc_bits(bytes_ptr));
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
  char * str = (char *) malloc(strsize);
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
    if (i % BLOCK_BYTE_LEN == 0) {
      blocks++;
    }
  }
  debug_print(1, "Number of blocks: %i (%i bytes, %i bits)\n", blocks, blocks * BLOCK_BYTE_LEN, blocks * BLOCK_LEN);
  return blocks;
}

htpa_blocks_array * split_into_blocks(htpa_bytes * bytes_ptr) {
  int blocks_total_num = calc_blocks_for_bytes(bytes_ptr);
  int block_num = 0;
  unsigned char * cursor = bytes_ptr->bytes; // a cursor to traverse the index of the actual bytes array

  debug_print(3, "Allocating memory for blocks array struct of size %i\n", blocks_total_num);

  // Allocate memory for a pointer to the array struct
  htpa_blocks_array *byte_streams_array = (htpa_blocks_array *) malloc(sizeof(htpa_blocks_array));
  debug_print(4, "Allocated memory for blocks array structure.%s","\n");

  // Allocate memory for blocks array pointer and each block struct
  byte_streams_array->size = blocks_total_num;
  byte_streams_array->blocks = (htpa_bytes **) malloc(sizeof(htpa_bytes *) * blocks_total_num);
  debug_print(4, "Allocated memory for %i block pointers for blocks array struct.\n", blocks_total_num);
  for (int i = 0; i < blocks_total_num; ++i)
  {
    byte_streams_array->blocks[i] = (htpa_bytes *) malloc(sizeof(htpa_bytes));
    byte_streams_array->blocks[i]->len = BLOCK_BYTE_LEN;
    // calloc() used because it fills the array with nulls. Useful because last block, if short, will leave those nulls as padding
    byte_streams_array->blocks[i]->bytes = (unsigned char *) calloc(BLOCK_BYTE_LEN, sizeof(unsigned char));
    debug_print(4, "Allocated memory for block %i of %i struct for array.\n", i+1, blocks_total_num);
  }

  // iterate through the long bytes_ptr byte stream and break it into blocks
  for (int i = 0; i < bytes_ptr->len; ++i) {
    int remaining_bytes = bytes_ptr->len - i;
    if (i % BLOCK_BYTE_LEN == 0) {
      ++block_num;
      if(remaining_bytes < BLOCK_BYTE_LEN) {
        // this / last block is short and needs "padding". Only copy the remaining bytes, leaving the rest of the block filled with NULLs
        int byte_pad_size = BLOCK_BYTE_LEN - remaining_bytes;
        debug_print(2, "Block %i of %i is short %i bytes (%i bits)! memcpy'ing only %i bytes\n", block_num, blocks_total_num, byte_pad_size, byte_pad_size * CHAR_BIT, remaining_bytes);
        memcpy(byte_streams_array->blocks[block_num-1]->bytes, cursor, remaining_bytes);
      } else {
        memcpy(byte_streams_array->blocks[block_num-1]->bytes, cursor, BLOCK_BYTE_LEN);
      }

      char *blck_txt = get_bytes_str(byte_streams_array->blocks[block_num-1]);
      char *blck_hex = get_bytes_hex(byte_streams_array->blocks[block_num-1]);
      debug_print(2, "Block %i of %i: \"%s\"\n", block_num, blocks_total_num, blck_txt);
      debug_print(2, "Block %i of %i: \"%s\"\n", block_num, blocks_total_num, blck_hex);
      free(blck_txt); blck_txt = NULL;
      free(blck_hex); blck_hex = NULL;

      // offset cursor to next block position for copying
      cursor = cursor + BLOCK_BYTE_LEN;
    }
  }

  return byte_streams_array;
}

void free_blocks_array(htpa_blocks_array *array_ptr) {
  debug_print(3, "Deallocating memory for blocks array struct of size %i.\n", array_ptr->size);
  for (int i = 0; i < array_ptr->size; ++i)
  {
    free(array_ptr->blocks[i]->bytes); array_ptr->blocks[i]->bytes = NULL;
    free(array_ptr->blocks[i]); array_ptr->blocks[i] = NULL;
    debug_print(4, "Freed block %i of %i in array\n", (i+1), array_ptr->size);
  }
  free(array_ptr->blocks); array_ptr->blocks = NULL;
  debug_print(4, "Freed blocks pointer%s", "\n");
  free(array_ptr); array_ptr = NULL;
  debug_print(4, "Freed blocks array!%s", "\n");
}

void pad_bytes(htpa_bytes * bytes_ptr) {
  int new_size = bytes_ptr->len + (BLOCK_BYTE_LEN - (bytes_ptr->len % BLOCK_BYTE_LEN));
  debug_print(3, "Resizing byte stream to a total of %i bytes (%i bits)\n", new_size, new_size * CHAR_BIT);
  bytes_ptr->bytes = (unsigned char *) realloc(bytes_ptr->bytes, new_size * sizeof(unsigned char));
  bytes_ptr->len = new_size;
}
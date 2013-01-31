#ifndef HTPA_H
#define HTPA_H

#include <stdio.h>
#include <limits.h>

// In bits
#define BLOCK_LEN 128
#define KEY_LEN 72
#define ROUND_KEY_LEN 64
#define BLOCK_HALF_LEN ((int) BLOCK_LEN / 2)

#define BLOCK_BYTE_LEN ((int) BLOCK_LEN / CHAR_BIT)
#define KEY_BYTE_LEN ((int) KEY_LEN / CHAR_BIT)
#define ROUND_BYTE_KEY_LEN ((int) ROUND_KEY_LEN / CHAR_BIT)
#define BLOCK_BYTE_HALF_LEN ((int) BLOCK_HALF_LEN / CHAR_BIT)


#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 1
#endif

typedef struct htpa_bytes_tag {
  int len;
  unsigned char *bytes;
} htpa_bytes;

typedef struct htpa_block_array_tag {
  int size;
  htpa_bytes **blocks;
} htpa_blocks_array;


void printf_blocks_array(htpa_blocks_array * array_ptr);
void fprint_bytes_hex(FILE *stream, htpa_bytes *);
void fprint_bytes_str(FILE *stream, htpa_bytes *);
char * get_bytes_hex(htpa_bytes *); // string of bytes represented hex, takes pointer to htpa_bytes struct
char * get_bytes_str(htpa_bytes *); // string of bytes represented ASCII, takes pointer to htpa_bytes struct

int calc_bits(htpa_bytes *); // Returns number of bits of byte array
int calc_blocks_for_bytes(htpa_bytes *); // Returns number of blocks needed in a byte array

htpa_blocks_array * split_into_blocks(htpa_bytes *); // breaks a byte array of any size into blocks (array of htpa_bytes)
void pad_bytes(htpa_bytes *); // reallocates space of byte stream to fit modulo BLOCK_BYTE_LEN
void free_blocks_array(htpa_blocks_array *); // Frees up memory of the blocks' byte arrays, the blocks themselves, and their array


#define debug_print(level, fmt, ...) \
        do { if (DEBUG && level <= DEBUG_LEVEL) fprintf(stderr, "%s:%d:%s(): [DEBUG %i] " fmt, __FILE__, \
                                __LINE__, __func__, level, __VA_ARGS__); fflush(stderr); } while (0)


#endif /* HTPA_H */

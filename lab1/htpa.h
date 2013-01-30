#ifndef HTPA_H
#define HTPA_H

#include <stdio.h>

// In bits
#define BLOCK_LEN 128
#define KEY_LEN 72
#define ROUND_KEY_LEN 64

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 1
#endif

typedef struct htpa_bytes_tag {
  int len;
  unsigned char *bytes;
} htpa_bytes;

typedef struct htpa_block_tag {
  int number;
  htpa_bytes *data;
} htpa_block;

void fprint_bytes_hex(FILE *stream, htpa_bytes *);
void fprint_bytes_str(FILE *stream, htpa_bytes *);
char * get_bytes_hex(htpa_bytes *); // string of bytes represented hex, takes pointer to htpa_bytes struct
char * get_bytes_str(htpa_bytes *); // string of bytes represented ASCII, takes pointer to htpa_bytes struct

int calc_bits(htpa_bytes *); // Returns number of bits of a string
int calc_blocks_for_bytes(htpa_bytes *); // Returns number of blocks needed

htpa_block ** split_into_blocks(htpa_bytes *); // breaks a string of any size into blocks (array of htpa_block)
// char* pad_block(char *str); // formats block into a padded BLOCK_LEN bit size
void free_blocks_array(htpa_block **);


#define debug_print(level, fmt, ...) \
        do { if (DEBUG && level <= DEBUG_LEVEL) fprintf(stderr, "%s:%d:%s(): [DEBUG %i] " fmt, __FILE__, \
                                __LINE__, __func__, level, __VA_ARGS__); fflush(stderr); } while (0)


#endif /* HTPA_H */

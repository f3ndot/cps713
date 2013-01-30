#ifndef HTPA_H
#define HTPA_H

// In bits
#define BLOCK_LEN 128
#define KEY_LEN 72
#define ROUND_KEY_LEN 64

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 1
#endif

typedef struct htpa_bytes {
  unsigned char *bytes;
  int len;
} htpa_bytes;

char * get_bytes_hex(htpa_bytes *); // string of bytes represented hex, takes pointer to htpa_bytes struct
char * get_bytes_str(htpa_bytes *); // string of bytes represented ASCII, takes pointer to htpa_bytes struct

int calc_bits(htpa_bytes * bytes); // Returns number of bits of a string
int calc_blocks_for_plaintext(char *str); // Returns number of blocks

char** split_into_blocks(char *str); // breaks a string of any size into blocks (array of strings)
char* pad_block(char *str); // formats block into a padded BLOCK_LEN bit size


#define debug_print(level, fmt, ...) \
        do { if (DEBUG && level <= DEBUG_LEVEL) fprintf(stderr, "%s:%d:%s(): [DEBUG %i] " fmt, __FILE__, \
                                __LINE__, __func__, level, __VA_ARGS__); fflush(stdout); } while (0)


#endif /* HTPA_H */

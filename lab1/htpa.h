#ifndef HTPA_H
#define HTPA_H

// In bits
#define BLOCK_LEN 128
#define KEY_LEN 72
#define ROUND_KEY_LEN 64

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 1
#endif

int calc_bits(char *str); // Returns number of bits of a string
int calc_blocks_for_plaintext(char *str); // Returns number of blocks

char** split_into_blocks(char *str); // breaks a string of any size into blocks (array of strings)
char* pad_block(char *str); // formats block into a padded BLOCK_LEN bit size


#define debug_print(level, fmt, ...) \
        do { if (DEBUG && level <= DEBUG_LEVEL) fprintf(stderr, "%s:%d:%s(): [DEBUG %i] " fmt, __FILE__, \
                                __LINE__, __func__, level, __VA_ARGS__); fflush(stderr); } while (0)




#endif /* HTPA_H */

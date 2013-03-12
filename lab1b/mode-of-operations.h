// Justin Bull 500355958
// Jonathan Kwan 500342079

#ifndef MOO_H
#define MOO_H

// has CHAR_BIT
#include <limits.h>

/* Algorithm size and length constants */
#define SANITY_KEYLEN 64
#define SANITY_KEYLEN_CHAR ((int) SANITY_KEYLEN / CHAR_BIT)
#define SANITY_PLAINLEN 8
#define SANITY_PLAINLEN_CHAR ((int) SANITY_PLAINLEN / CHAR_BIT)
#define HILL_KEYLEN SANITY_KEYLEN
#define HILL_KEYLEN_CHAR SANITY_KEYLEN_CHAR
#define HILL_HEADER_LEN 6
#define IVTABLE_SIZE 1024
#define IVTABLE_BITMAP_SIZE ((int) IVTABLE_SIZE / 8)

/* mode of operations in hill cipher */
#define HILL_MODE_ECB 0
#define HILL_MODE_CBC 1
#define HILL_MODE_OFB 2
#define HILL_IV_ECB 0
#define HILL_IV_TABLE 1
#define HILL_IV_UNUSED -1

/* Hill Cipher encryption and decryption functions */
unsigned char * hill_cipher_encrypt(unsigned char *ciphertext, unsigned char *plaintext, int len, unsigned char *key, int mode, unsigned char iv, int iv_flag);
unsigned char * hill_cipher_decrypt(unsigned char *plaintext, unsigned char *ciphertext, int len, unsigned char *dkey);
unsigned char matrix_mult_vector(unsigned char *matrix, unsigned char vector);
void save_bytes_to_file(char *filename, unsigned char *bytes, int len);
void printhex(unsigned char *bytes, int len);

FILE * generate_iv_table(char *filename);
unsigned char consume_next_available_iv(FILE *table_fp);

/* debug and utility functions */
#ifndef DEBUG
#define DEBUG 0
#endif
#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 1
#endif

#define debug_print(level, fmt, ...) \
        do { if (DEBUG && level <= DEBUG_LEVEL) fprintf(stderr, "%s:%d:%s(): [DEBUG %i] " fmt, __FILE__, \
                                __LINE__, __func__, level, __VA_ARGS__); fflush(stderr); } while (0)

#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARYPATTERNSPACE "%d %d %d %d %d %d %d %d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0)

#endif /* MOO_H */

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
#define IVTABLE_SIZE 1024
#define IVTABLE_BITMAP_SIZE ((int) IVTABLE_SIZE / 8)

/* mode of operations in hill cipher */
#define HILL_MODE_ECB 0x00
#define HILL_MODE_CBC 0x01
#define HILL_MODE_CFB 0x02
#define HILL_IV_ECB 0x00
#define HILL_IV_TABLE 0x80
#define HILL_UNUSED 0x00

/* encryption header definitions */
/*
 *  0                2        3        4                                8        9
 *  +----------------+--------+--------+--------------------------------+--------+
 *  | "HC" magic str | Flags  |   IV   |         IV Table Index         |  Ver.  |
 *  |    2 bytes     | 1 byte | 1 byte |     4 bytes (unsigned int)     | 1 byte |
 *  +----------------+--------+--------+--------------------------------+--------+
 *
 *  1. "HC" magic str identifies file as an encrypted file
 *  2. Flags contains the encryption block mode and IV source:
 *     - 1XXXXXX = IV index is specified and IV must be looked up in public table
 *     - XXXXX00 = Block mode is ECB
 *     - XXXXX01 = Block mode is CBC
 *     - XXXXX10 = Block mode is CFB
 *  3. IV is the IV value used in CBC or CFG but encrypted with Hill Cipher in ECB mode
 *  4. IV Table Index is the location of the IV value in the generated nonce IV table.
 *  5. Version specifies what implementation version this encrypted file is.
 *
 */

#define HILL_HEADER_MODE_MASK 0x03
#define HILL_HEADER_IV_MASK 0x80
typedef struct hillcipher_header_tag
{
  unsigned char magic[2];
  unsigned char flags; // 0x80 = IV table, 0x00 = ECB mode, 0x01 = CBC mode, 0x02 = CFB mode
  unsigned char iv;
  unsigned int iv_index;
  unsigned char version;
} hillcipher_header;
#define HILL_HEADER_LEN 9

void init_header_struct(hillcipher_header *header); // inits default values
void build_header_struct(hillcipher_header *header, unsigned char *data); // used to create header struct from bytestream

/* Hill Cipher encryption and decryption functions */
unsigned char * hill_cipher_encrypt(unsigned char *ciphertext, unsigned char *plaintext, int len, unsigned char *key, int mode, unsigned char iv, int iv_index);
unsigned char * hill_cipher_decrypt(unsigned char *plaintext, unsigned char *ciphertext, int len, unsigned char *dkey);
unsigned char matrix_mult_vector(unsigned char *matrix, unsigned char vector);
void save_bytes_to_file(char *filename, unsigned char *bytes, int len);
void printhex(unsigned char *bytes, int len);

FILE * generate_iv_table(char *filename);
unsigned char consume_next_available_iv(FILE *table_fp, int *iv_index);
unsigned char lookup_iv_in_table(int iv_index);

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

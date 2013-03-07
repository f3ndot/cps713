// Justin Bull 500355958

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

/* Used in masking out desired bits in matrix multiplication */
const unsigned char hill_row_masks[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

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


unsigned char matrix_mult_vector(unsigned char *matrix, unsigned char vector);

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

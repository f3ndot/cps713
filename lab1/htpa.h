#ifndef HTPA_H
#define HTPA_H

#define BLOCK_LEN 128
#define KEY_LEN 72
#define ROUND_KEY_LEN 64

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 1
#endif

#define debug_print(level, fmt, ...) \
        do { if (DEBUG && level <= DEBUG_LEVEL) fprintf(stderr, "%s:%d:%s(): [DEBUG %i] " fmt, __FILE__, \
                                __LINE__, __func__, level, __VA_ARGS__); fflush(stderr); } while (0)




#endif /* HTPA_H */
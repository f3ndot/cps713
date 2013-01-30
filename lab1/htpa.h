#ifndef HTPA_H
#define HTPA_H

#ifndef BLOCK_LEN
#define BLOCK_LEN 128
#endif

#ifndef KEY_LEN
#define KEY_LEN 72
#endif

#define debug_print(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): [DEBUG] " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)


#endif /* HTPA_H */
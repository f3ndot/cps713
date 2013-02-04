#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0)

const unsigned int pbox[64] = {
  57, 49, 41, 33, 25, 17,  9, 1,
  58, 50, 42, 34, 26, 18, 10, 2,
  59, 51, 43, 35, 27, 19, 11, 3,
  60, 52, 44, 36, 28, 20, 12, 4,
  64, 59, 48, 40, 32, 24, 16, 8,
  63, 55, 47, 39, 31, 23, 15, 7,
  62, 54, 46, 38, 30, 22, 14, 6,
  61, 53, 45, 37, 29, 21, 13, 5
};

int get_bit(unsigned char byte, int position) {
  int mask =  1 << (7 - position);
  // printf("Mask:"BYTETOBINARYPATTERN"\n", BYTETOBINARY(mask));
  int masked_n = byte & mask;
  return masked_n >> (7 - position);
}

void get_bits_on_bytes(int *bits, int *positions, unsigned char *bytes, int bits_len) {
  int i; int bit;

  for (i = 0; i < bits_len; ++i) {
    int byte_pos = floor((double) i/8);
    bits[i] = get_bit(bytes[byte_pos], i%8);
    positions[i] = i;
  }
}

unsigned char set_bits_on_byte(unsigned char byte, int *positions, int *bits) {
  int i;
  unsigned char new_byte = 0x00;
  for (i = 0; i < 8; ++i) {
    int new_bit = bits[i] << positions[i];
    if((new_byte & new_bit)) {
      fprintf(stderr, "ERROR: Bit already set. Position array is malformed?\n");
      exit(EXIT_FAILURE);
    }
    new_byte |= new_bit;
  }

  return new_byte;
}

int main(int argc, char **argv) {
  int i;

  int bit[64];
  int pos[64];
  unsigned char str[9] = "MyGodKey";
  get_bits_on_bytes(bit, pos, str, 64);

  printf("Before Permutation:\n");
  for (i = 0; i < 64; ++i) {
    if(i % 8 == 0 && i > 0) putchar('\n');
    printf("%i @%2d\t\t",bit[i], pos[i]);
  }
  putchar('\n');
  putchar('\n');
  putchar('\n');

  printf("Expected PBOX Mapping:\n");
  for (i = 0; i < 64; ++i) {
    if(i % 8 == 0 && i > 0) putchar('\n');
    printf("%i->%2d\t\t",bit[i], pbox[i]-1);
  }

  putchar('\n');
  printf("---------------------\n");
  putchar('\n');

  int tmp_bit[64];
  for (i = 0; i < 64; ++i) {
    int j;
    tmp_bit[pbox[i]-1] = bit[i];
  }

  printf("After Permutation:\n");
  for (i = 0; i < 64; ++i) {
    if(i % 8 == 0 && i > 0) putchar('\n');
    printf("%i @%2d\t\t",tmp_bit[i], i);
  }
  putchar('\n');
  putchar('\n');
  putchar('\n');




  return 0;
}
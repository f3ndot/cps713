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
  int mask =  1 << (position-1);
  // printf("Mask:"BYTETOBINARYPATTERN"\n", BYTETOBINARY(mask));
  int masked_n = byte & mask;
  return masked_n >> (position-1);
}

void set_bits_on_bytes(unsigned char *bytes, int *bits, int bits_len) {
  int i; int bit;

  for (i = 0; i < bits_len; ++i) {
    int byte_pos = floor((double) i/8);
    int mask = 1 << (7 - i%8);
    // printf("MASK:"BYTETOBINARYPATTERN"\n", BYTETOBINARY(mask));

    // need to clear
    if(bits[i] == 0) {
      int value = 0 << (7 - i%8);
      bytes[byte_pos] = ((bytes[byte_pos] & ~mask) | (value & mask));
    // need to set
    } else {
      int value = 1 << (7 - i%8);
      bytes[byte_pos] = ((bytes[byte_pos] & ~mask) | (value & mask));
    }
  }
}

void get_bits_on_bytes(int *bits, int *positions, unsigned char *bytes, int bits_len) {
  int i; int bit;

  for (i = 0; i < bits_len; ++i) {
    int byte_pos = floor((double) i/8);
    bits[i] = get_bit(bytes[byte_pos], i%8);
    positions[i] = i;
  }
}

int main(int argc, char **argv) {

  unsigned char test[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};

  int storage_bits[64];

  for (int i = 0; i < 64; ++i) {
    int byte_pos = (int) floor((double) i/8);
    printf("Char: %i, Pos: %i -> Val: %i\n", byte_pos, (i%8)+1, get_bit(test[byte_pos], (i%8)+1) );
    storage_bits[i] = get_bit(test[byte_pos], (i%8)+1);
  }



  for (int i = 0; i < 64; ++i)
  {
    if(i % 8 == 0 && i > 0) putchar('\n');
    int byte_pos = (int) floor((double) i/8);
    int weird_bit_index = ((byte_pos * 8) + (8 - i%8)) - 1;

    printf("%2i  ", storage_bits[weird_bit_index]);
    // printf("%2i  ", 8-(i%8));
  }


  printf("Expected PBOX Mapping:\n");
  for (int i = 0; i < 64; ++i) {
    if(i % 8 == 0 && i > 0) putchar('\n');
    int byte_pos = (int) floor((double) i/8);
    int weird_bit_index = ((byte_pos * 8) + (8 - i%8)) - 1;

    printf("%2d->%2d\t\t", weird_bit_index+1, pbox[weird_bit_index]);
  }

  putchar('\n');

  // unsigned char test[] = "AB";
  // printf("Char 0:"BYTETOBINARYPATTERN"\n", BYTETOBINARY(test[0]));
  // printf("Char 1:"BYTETOBINARYPATTERN"\n", BYTETOBINARY(test[1]));

  // int bits[] = {
  //   1,1,1,1,0,0,0,0,
  //   0,0,1,1,0,0,1,1
  // };

  // set_bits_on_bytes(test, bits, 16);

  // printf("Char 0:"BYTETOBINARYPATTERN"\n", BYTETOBINARY(test[0]));
  // printf("Char 1:"BYTETOBINARYPATTERN"\n", BYTETOBINARY(test[1]));

  // int i;

  // int bit[64];
  // int pos[64];
  // unsigned char str[9] = "MyGodKey";
  // get_bits_on_bytes(bit, pos, str, 64);

  // printf("Before Permutation: %s\n", str);
  // printf("Before Permutation:\n");
  // for (i = 0; i < 64; ++i) {
  //   if(i % 8 == 0 && i > 0) putchar('\n');
  //   printf("%i @%2d\t\t",bit[i], pos[i]);
  // }
  // putchar('\n');
  // putchar('\n');
  // putchar('\n');

  // printf("Expected PBOX Mapping:\n");
  // for (i = 0; i < 64; ++i) {
  //   if(i % 8 == 0 && i > 0) putchar('\n');
  //   printf("%i->%2d\t\t",bit[i], pbox[i]-1);
  // }

  // putchar('\n');
  // printf("---------------------\n");
  // putchar('\n');

  // int tmp_bit[64];
  // for (i = 0; i < 64; ++i) {
  //   int j;
  //   tmp_bit[pbox[i]-1] = bit[i];
  // }

  // printf("After Permutation:\n");
  // for (i = 0; i < 64; ++i) {
  //   if(i % 8 == 0 && i > 0) putchar('\n');
  //   printf("%i @%2d\t\t",tmp_bit[i], i);
  // }
  // putchar('\n');
  // putchar('\n');
  // putchar('\n');




  return 0;
}
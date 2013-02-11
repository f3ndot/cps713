#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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


int main(int argc, char **argv) {
  int i;
  unsigned char str[10] = "MyKeyGood";
  unsigned char str2[8] = { 0x00 };

  printf("Key: ");
  for (i = 0; i < 9; ++i) {
    printf("%c", str[i]);
  }
  putchar('\n');
  for (i = 0; i < 9; ++i) {
    printf("0x%.2X ", str[i]);
  }
  putchar('\n');
  for (i = 0; i < 9; ++i) {
    printf (BYTETOBINARYPATTERN" ", BYTETOBINARY(str[i]));
  }
  putchar('\n');
  putchar('\n');
  putchar('\n');

  for (i = 0; i < 8; ++i) {
    printf ("START:    "BYTETOBINARYPATTERN" \n", BYTETOBINARY(str[i]));

    // shift-left entire byte by i bits because of previous byte taking i bits of this one
    str[i] = str[i] << i+1;
    printf ("SHIFT LF: "BYTETOBINARYPATTERN" (Shift Left %i Bits)\n", BYTETOBINARY(str[i]), i+1);

    // // Remove/Mask out the last i+1 bits (i because of previous + 1 new bit to be removed)
    // str[i] = str[i] >> i+1;
    // str[i] = str[i] << i+1;
    // printf ("REM LAST: "BYTETOBINARYPATTERN" (Moved Right-Left %i Bits)\n", BYTETOBINARY(str[i]), (i+1));

    // shift next byte's first-most i+1 bits to the right-most (position 8)

    // remove next byte's left-most bit
    unsigned char temp = str[i+1] << 1;
    printf ("NXT SHFT: "BYTETOBINARYPATTERN" (Shift Left %i Bits)\n", BYTETOBINARY(temp), 1);
    temp = temp >> (7 - i);
    printf ("NXT SHFT: "BYTETOBINARYPATTERN" (Shift Right %i Bits)\n", BYTETOBINARY(temp), (7 - i) );

    // combine/bitwise-OR the result
    str2[i] = str[i] | temp;
    printf ("BOR BOTH: "BYTETOBINARYPATTERN" \n", BYTETOBINARY(str2[i]));
    printf("---------------\n");
  }

  // printf("\n\nMasked out 8th bit of every byte in key:\n-----------");

  printf("\n\nKey: ");
  for (i = 0; i < 8; ++i) {
    printf("%c", str2[i]);
  }
  putchar('\n');
  for (i = 0; i < 8; ++i) {
    printf("0x%.2X ", str2[i]);
  }
  putchar('\n');
  for (i = 0; i < 8; ++i) {
    printf (BYTETOBINARYPATTERN" ", BYTETOBINARY(str2[i]));
  }
  putchar('\n');
  putchar('\n');


  return 0;
}

// 01001101 01111001 01001011 01100101 01111001 01000111 01101111 01101111 01100100
// 10011011 11100110 01011110 01011111 00110001 11110111 11101111 10010000



// 01001100 11110001 00101011 00100111 10001000 11011011 10110111 01100100

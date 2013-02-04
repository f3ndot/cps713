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

    str[i] = str[i] << i;
    printf ("SHIFT LF: "BYTETOBINARYPATTERN" (Shift Left %i Bits)\n", BYTETOBINARY(str[i]), i);

    // Remove/Mask out the last i+1 bits (amount relative to char position in string)
    str[i] = str[i] >> i+1;
    str[i] = str[i] << i+1;
    printf ("REM LAST: "BYTETOBINARYPATTERN" (Moved Right-Left %i Bits)\n", BYTETOBINARY(str[i]), (i+1));

    // remove the next byte's 2nd-8th bits (leaving 1st bit intact)
    unsigned char temp;
    printf ("NXT STRT: "BYTETOBINARYPATTERN" \n", BYTETOBINARY(str[i+1]));
    temp = str[i+1] >> (8 - (i+1)); // mask is 10000000
    temp = temp << (8 - (i+1)); // mask is 10000000
    printf ("NXT REMF: "BYTETOBINARYPATTERN" (Moved Right-Left %i Bits)\n", BYTETOBINARY(temp), (8 - (i+1)));

    // shift next byte's 1st-bit it 7 bits to the right (position 8)
    temp = temp >> (8 - (i+1));
    printf ("NXT SHFT: "BYTETOBINARYPATTERN" (Shift Right %i Bits)\n", BYTETOBINARY(temp), (8 - (i+1)));

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
// 01001100 11110001 00101011 00100111 10001000 11011011 10110111 01100100

// 01001100 111100XX 01001011 01100101 01111001 01000111 01101111 01101111 01100100


// next I would allocate some memory for a new string, and begin writing to it 1 byte at a time
// so str2[x]=str[x]
// then, the only relevant info to stripping off that last bit is the first bit of the next byte
// so, And the next byte by 10000000 (0x80) and then shift it right 7 bits.
// then, you'll have a value representing the highest order bit of the next byte, which you will place into the lowest order bit field of the new byte
// so after you strip out the lowest-order bit from str in the first place which you have already done: str2[x]=str[x]
// BYTE BitFromNextByteToMoveToPrevious=((str[x + 1] & 0x80) >> 7);
// and then just str2[x] |= BitFromNextByteToMoveToPrevious;
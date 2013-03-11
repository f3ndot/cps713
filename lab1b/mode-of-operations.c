// Justin Bull 500355958
// Jonathan Kwan 500342079

#define DEBUG 0
#define DEBUG_LEVEL 2

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include "mode-of-operations.h"

int main(int argc, char const *argv[])
{
  int i = 0;


  /*
   * Perform sanity check on the encryption and decryption functions.
   */
  unsigned char key[SANITY_KEYLEN_CHAR] =
  {
    0xC0, // 1 1 0 0 0 0 0 0
    0x60, // 0 1 1 0 0 0 0 0
    0x30, // 0 0 1 1 0 0 0 0
    0x18, // 0 0 0 1 1 0 0 0
    0x0C, // 0 0 0 0 1 1 0 0
    0x06, // 0 0 0 0 0 1 1 0
    0x03, // 0 0 0 0 0 0 1 1
    0x01  // 0 0 0 0 0 0 0 1
  };
  unsigned char dkey[SANITY_KEYLEN_CHAR] =
  {
    0xFF, // 1 1 1 1 1 1 1 1
    0x7F, // 0 1 1 1 1 1 1 1
    0x3F, // 0 0 1 1 1 1 1 1
    0x1F, // 0 0 0 1 1 1 1 1
    0x0F, // 0 0 0 0 1 1 1 1
    0x07, // 0 0 0 0 0 1 1 1
    0x03, // 0 0 0 0 0 0 1 1
    0x01  // 0 0 0 0 0 0 0 1
  };

  if(DEBUG == 1) {
    printf("Encipherment Sanity Check!\n");
    for (i = 0; i < SANITY_KEYLEN_CHAR; ++i)
    {
      printf("Key Matrix (row %d): [ "BYTETOBINARYPATTERNSPACE" ]\n", i+1, BYTETOBINARY(key[i]));
    }

    unsigned char plain[SANITY_PLAINLEN_CHAR] = { 0xA5 }; // 10100101
    printf("Provided Plaintext:  ");
    for (i = 0; i < SANITY_PLAINLEN_CHAR; ++i)
    {
      printf(BYTETOBINARYPATTERN" ", BYTETOBINARY(plain[i]));
    }
    printf("\n");


    unsigned char sanity_ciphertext = matrix_mult_vector(key, plain[0]);
    printf("Expected Ciphertext: 11101111\n");
    printf("Computed Ciphertext: "BYTETOBINARYPATTERN"\n", BYTETOBINARY(sanity_ciphertext));

    if(sanity_ciphertext == 0xEF) { // aka 11101111
      printf("Encipherment Sanity Check OK! Proceeding!\n\n");
    } else {
      fprintf(stderr, "ERROR!!! SANITY CHECK FOR ENCIPHERMENT FAILED!\n");
      exit(EXIT_FAILURE);
    }

    printf("Decryption Sanity Check!\n");
    for (i = 0; i < SANITY_KEYLEN_CHAR; ++i)
    {
      printf("Inv Key Matrix (row %d): [ "BYTETOBINARYPATTERNSPACE" ]\n", i+1, BYTETOBINARY(dkey[i]));
    }
    unsigned char sanity_decryped_plaintext = matrix_mult_vector(dkey, sanity_ciphertext);
    printf("Expected Decryption: "BYTETOBINARYPATTERN"\n", BYTETOBINARY(plain[0]));
    printf("Computed Decryption: "BYTETOBINARYPATTERN"\n", BYTETOBINARY(sanity_decryped_plaintext));
    if(sanity_decryped_plaintext == plain[0]) { // aka 11101111
      printf("Decryption Sanity Check OK! Proceeding!\n\n");
    } else {
      fprintf(stderr, "ERROR!!! SANITY CHECK FOR DECRYPTION FAILED!\n");
      exit(EXIT_FAILURE);
    }
  }

  /*
   * Quickly check for input
   */
  int encipherment_mode = -1;
  int block_mode = -1;
  char output_file[1024]; // filename is max 1024 chars...

  if(argc < 2) {
    fprintf(stderr, "Dude! You need to input a message or specify a file! Exiting...\n");
    exit(EXIT_FAILURE);
  }

  printf("Are you (1) encrypting or (2) decrypting?\n\nEnter choice: ");
  scanf("%d", &encipherment_mode);
  printf("Available Modes of Operation:\n(1) ECB\t\t(2) CBC\n\nEnter choice: ");
  scanf("%d", &block_mode);
  printf("Where should we save the output / resulting bytes? Type \"none\" to not save to a file\n\nEnter filename: ");
  scanf("%s", output_file);

  if(encipherment_mode != 1 && encipherment_mode != 2 && block_mode != 1 && block_mode != 2) {
    fprintf(stderr, "Dude! Invalid choices! Exiting...\n");
    exit(EXIT_FAILURE);
  }


  /*
   * Proceed with actual program
   */
  unsigned char *ct, *pt, *dpt;
  int msglen;

  // determine if its a file or small plaintext string
  FILE *fp = fopen(argv[1], "rb");
  size_t bytes_read;
  if(fp) {
    // get the full bytesize of file
    fseek(fp, 0L, SEEK_END);
    msglen = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    debug_print(1, "Opened file \"%s\" for plaintext\n", argv[1]);

    ct  = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    pt  = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    dpt = (unsigned char *) calloc(msglen, sizeof(unsigned char));

    // char *buf = (char *) malloc(msglen * sizeof(unsigned char));
    bytes_read = fread(pt, sizeof(char), msglen, fp);
    debug_print(1, "Read %i bytes from file %s\n", (int) bytes_read, argv[1]);

    fclose(fp);
  } else {
    debug_print(1, "Argument is not a file or cannot read, assuming \"%s\" to be plaintext\n", argv[1]);

    msglen = strlen(argv[1]);
    ct  = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    pt  = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    dpt = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    memcpy(pt, argv[1], msglen);
  }


  if(encipherment_mode == 1) {
    printf("Original Plaintext:   \"");
    for (i = 0; i < msglen; ++i)
    {
      putchar(pt[i]);
    }
    printf("\"\n");

    hill_cipher_encrypt(ct, pt, msglen, key, HILL_MODE_ECB);
    printf("Encrypted Ciphertext: "); printhex(ct, msglen); printf("\n");

    save_bytes_to_file(output_file, ct, msglen);
  }
  if(encipherment_mode == 2) {
    hill_cipher_decrypt(dpt, pt, msglen, dkey, HILL_MODE_ECB);
    printf("Original Ciphertext:  "); printhex(dpt, msglen); printf("\n");
    printf("Decrypted Plaintext:  "); printhex(dpt, msglen); printf("\n");
    printf("Decrypted Plaintext:  \"");
    for (i = 0; i < msglen; ++i)
    {
      putchar(dpt[i]);
    }
    printf("\"\n");

    save_bytes_to_file(output_file, dpt, msglen);
  }


  free(ct);
  free(pt);
  free(dpt);
  exit(EXIT_SUCCESS);
}


void save_bytes_to_file(char *filename, unsigned char *bytes, int len)
{
  if(strcmp(filename, "none") == 0) return;

  FILE *ofp = fopen(filename, "wb");
  if(ofp) {
    fwrite(bytes, len, 1, ofp);
    fclose(ofp);
  }
}


unsigned char * hill_cipher_encrypt(unsigned char *ciphertext, unsigned char *plaintext, int len, unsigned char *key, int mode)
{
  int i;
  if(mode == HILL_MODE_ECB) {
    // iterate through plaintext and encrypt block-by-block without any sort of chaining..
    for (i = 0; i < len; ++i)
    {
      ciphertext[i] = matrix_mult_vector(key, plaintext[i]);
    }
    return ciphertext;
  }
  fprintf(stderr, "ERROR: Unknown hill cipher mode!\n","");
  return NULL;
}


unsigned char * hill_cipher_decrypt(unsigned char *plaintext, unsigned char *ciphertext, int len, unsigned char *dkey, int mode)
{
  int i;
  if(mode == HILL_MODE_ECB) {
    // iterate through plaintext and encrypt block-by-block without any sort of chaining..
    for (i = 0; i < len; ++i)
    {
      plaintext[i] = matrix_mult_vector(dkey, ciphertext[i]);
    }
    return plaintext;
  }
  fprintf(stderr, "ERROR: Unknown hill cipher mode!\n","");
  return NULL;
}


unsigned char matrix_mult_vector(unsigned char *matrix, unsigned char vector)
{
  // the resulting "vector"
  unsigned char result = 0x00;

  int i;
  for (i = 0; i < HILL_KEYLEN_CHAR; ++i)
  {
    // a row of the matrix is multiplied by a vector under GF(2)
    // aka AND each bit in matrix and vector and XOR their results
    // int bit holds either 1 or 0
    int bit = ((matrix[i] & vector & 0x80) >> 7) ^
              ((matrix[i] & vector & 0x40) >> 6) ^
              ((matrix[i] & vector & 0x20) >> 5) ^
              ((matrix[i] & vector & 0x10) >> 4) ^
              ((matrix[i] & vector & 0x08) >> 3) ^
              ((matrix[i] & vector & 0x04) >> 2) ^
              ((matrix[i] & vector & 0x02) >> 1) ^
              ((matrix[i] & vector & 0x01) >> 0);

    // take bit result from matrix row and vector mult and move it into appropriate location, combining with previously set bits
    result |= (bit << (7-i));
    debug_print(2, BYTETOBINARYPATTERN" * "BYTETOBINARYPATTERN" = %d\n", BYTETOBINARY(matrix[i]), BYTETOBINARY(vector), bit);
  }

  debug_print(1, "Result: "BYTETOBINARYPATTERN"\n", BYTETOBINARY(result));
  return result;
}

void printhex(unsigned char *bytes, int len)
{
  int i;
  for (i = 0; i < len; i++)
  {
    printf("0x%02X ", bytes[i]);
  }
}
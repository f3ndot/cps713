// Justin Bull 500355958
// Jonathan Kwan 500342079

#define DEBUG 1
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
  srandomdev(); // seeds random number generator from OS

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

  if(DEBUG == 1)
  {
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

    if(sanity_ciphertext == 0xEF) // aka 11101111
    {
      printf("Encipherment Sanity Check OK! Proceeding!\n\n");
    }
    else
    {
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
    if(sanity_decryped_plaintext == plain[0]) // aka 11101111
    {
      printf("Decryption Sanity Check OK! Proceeding!\n\n");
    }
    else
    {
      fprintf(stderr, "ERROR!!! SANITY CHECK FOR DECRYPTION FAILED!\n");
      exit(EXIT_FAILURE);
    }
  }

  /*
   * Quickly check for input and prepare values accordingly
   */
  int encipherment_mode = -1;
  int block_mode = -1;
  int iv_source = -1;
  char output_file[1024]; // filename is max 1024 chars...
  char ivtable_file[] = "ivtable.bin";
  char iv;

  if(argc < 2)
  {
    fprintf(stderr, "Dude! You need to input a message or specify a file! Exiting...\n");
    exit(EXIT_FAILURE);
  }

  printf("Are you (1) encrypting or (2) decrypting?\n\nEnter choice: ");
  scanf("%d", &encipherment_mode);

  // if encrypting, prompt for encryption strategy
  if(encipherment_mode == 1)
  {

    printf("Available Modes of Operation:\n(1) ECB\t\t(2) CBC\n\nEnter choice: ");
    scanf("%d", &block_mode);

    // if CBC mode has been chosen
    if(block_mode == 2 && encipherment_mode == 1)
    {
      printf("Do you want to (1) randomly select an IV or (2) use a public nonce IV table?\n\nEnter choice: ");
      scanf("%d", &iv_source);
      if(iv_source == 1)
      {

      }
      else if(iv_source == 2)
      {
        FILE *iv_fp = fopen(ivtable_file, "r+b");
        if(iv_fp)
        {
          iv = consume_next_available_iv(iv_fp);
          fclose(iv_fp);
        }
        else
        {
          printf("Nonce-generated IV lookup table doesn't exist! Generating %d nonce values...\n", IVTABLE_SIZE);
          FILE *iv_fp2;
          iv_fp2 = generate_iv_table(ivtable_file);
          iv = consume_next_available_iv(iv_fp2);
          fclose(iv_fp2);
        }
      }
    }

  } // end if(encipherment_mode == 1)
  // if decrypting, look up encryption header to determine ECB or CBC and with what IV type
  else if(encipherment_mode == 2)
  {
    // TODO
  }

  printf("Where should we save the output / resulting bytes? Type \"none\" to not save to a file\n\nEnter filename: ");
  scanf("%s", output_file);

  if(encipherment_mode != 1 && encipherment_mode != 2 && block_mode != 1 && block_mode != 2)
  {
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
  if(fp)
  {
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
  }
  else
  {
    debug_print(1, "Argument is not a file or cannot read, assuming \"%s\" to be plaintext\n", argv[1]);

    msglen = strlen(argv[1]);
    ct  = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    pt  = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    dpt = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    memcpy(pt, argv[1], msglen);
  }


  if(encipherment_mode == 1)
  {
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
  if(encipherment_mode == 2)
  {
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
  if(ofp)
  {
    fwrite(bytes, len, 1, ofp);
    fclose(ofp);
  }
}


unsigned char * hill_cipher_encrypt(unsigned char *ciphertext, unsigned char *plaintext, int len, unsigned char *key, int mode)
{
  int i;
  if(mode == HILL_MODE_ECB)
  {
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
  if(mode == HILL_MODE_ECB)
  {
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


unsigned char consume_next_available_iv(FILE *table_fp)
{
  const int table_sz = IVTABLE_SIZE;
  int i;
  int bit_pos = -1;
  unsigned char tmp;
  long opos = ftell(table_fp);
  fseek(table_fp, 0L, SEEK_SET);

  // find the first unused iv in bitmap and access it's location
  for (i = 0; i < (table_sz/8); ++i)
  {
    tmp = (unsigned char) fgetc(table_fp);
    debug_print(2, "Inspecting index byte 0x%.2X \n", tmp);

    if((tmp & 0x80) == 0) { bit_pos = (i*8) + 0; tmp |= 0x80; break; }
    if((tmp & 0x40) == 0) { bit_pos = (i*8) + 1; tmp |= 0x40; break; }
    if((tmp & 0x20) == 0) { bit_pos = (i*8) + 2; tmp |= 0x20; break; }
    if((tmp & 0x10) == 0) { bit_pos = (i*8) + 3; tmp |= 0x10; break; }
    if((tmp & 0x08) == 0) { bit_pos = (i*8) + 4; tmp |= 0x08; break; }
    if((tmp & 0x04) == 0) { bit_pos = (i*8) + 5; tmp |= 0x04; break; }
    if((tmp & 0x02) == 0) { bit_pos = (i*8) + 6; tmp |= 0x02; break; }
    if((tmp & 0x01) == 0) { bit_pos = (i*8) + 7; tmp |= 0x01; break; }
    debug_print(2, "Bitmap byte no. %d exhausted... Moving on...\n", i);
  }

  if(bit_pos == -1)
  {
    fprintf(stderr, "ERROR! The IV Table has been exhausted! Please delete and regenerate. Dying...\n");
    exit(EXIT_FAILURE);
  }

  // immediately burn the index. int i should be the byte index
  debug_print(2, "Bitmap byte at offset %d being updated to indicate used IV...\n", i);
  fseek(table_fp, i, SEEK_SET);
  fputc(tmp, table_fp);

  // put pointer in position for obtaining IV value
  fseek(table_fp, IVTABLE_BITMAP_SIZE + bit_pos, SEEK_SET);
  tmp = (unsigned char) fgetc(table_fp);

  debug_print(1, "Usable IV value 0x%.2X at index %d obtained\n", tmp, bit_pos);

  // return pointer to its original location
  fseek(table_fp, opos, SEEK_SET);
  return tmp;
}

FILE * generate_iv_table(char *filename)
{
  const int table_sz = IVTABLE_SIZE;
  int i;
  FILE *fp = fopen(filename, "w+b");

  if(table_sz % 8 != 0)
  {
    fprintf(stderr, "WHOA! Developer error: IVTABLE_SIZE (%d) is not divisible by 8. Violates my lazy bitmapping implementation. Dying...\n", table_sz);
    exit(EXIT_FAILURE);
  }

  // generate the bitmap of used values and set all to zero (unused)
  for (i = 0; i < (table_sz/8); ++i)
  {
    fputc(0x00, fp);
  }
  for (i = 0; i < table_sz; ++i)
  {
    unsigned char val = (unsigned char) random();
    fwrite(&val, 1, 1, fp);
  }

  return fp;
}

void printhex(unsigned char *bytes, int len)
{
  int i;
  for (i = 0; i < len; i++)
  {
    printf("0x%02X ", bytes[i]);
  }
}
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


  /*
   * Check for input and prepare values accordingly
   */
  int encipherment_mode = -1;
  int block_mode = -1;
  int iv_source = -1;
  char output_file[1024]; // filename is max 1024 chars...
  char ivtable_file[] = "ivtable.bin";
  unsigned char iv = HILL_UNUSED;
  int iv_index = HILL_UNUSED;
  char manual_iv[8+1];

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

    printf("Available Modes of Operation:\n(1) ECB\t\t(2) CBC\t\t(3) CFB\n\nEnter choice: ");
    scanf("%d", &block_mode);
    block_mode -= 1;

    // if CBC mode has been chosen
    if(block_mode != HILL_MODE_ECB && encipherment_mode == 1)
    {
      printf("Do you want to (1) randomly select an IV or (2) use a public nonce IV table?\n\nEnter choice: ");
      scanf("%d", &iv_source);
      if(iv_source == 1)
      {
        printf("Enter in desired IV value in binary (eg 10101100)\n\nEnter IV: ");
        scanf("%s", manual_iv);
        iv = (unsigned char) strtol(manual_iv, NULL, 2);
        debug_print(1, "Parsed manual IV input as 0x%2X\n", iv);
      }
      else if(iv_source == 2)
      {
        FILE *iv_fp = fopen(ivtable_file, "r+b");
        if(iv_fp)
        {
          iv = consume_next_available_iv(iv_fp, &iv_index);
          fclose(iv_fp);
        }
        else
        {
          printf("Nonce-generated IV lookup table doesn't exist! Generating %d nonce values...\n", IVTABLE_SIZE);
          FILE *iv_fp2;
          iv_fp2 = generate_iv_table(ivtable_file);
          iv = consume_next_available_iv(iv_fp2, &iv_index);
          fclose(iv_fp2);
        }
      }
    }

  } // end if(encipherment_mode == 1)

  printf("Where should we save the output / resulting bytes? Type \"none\" to not save to a file\n\nEnter filename: ");
  scanf("%s", output_file);


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

    pt  = (unsigned char *) calloc(msglen, sizeof(unsigned char));
    bytes_read = fread(pt, sizeof(char), msglen, fp);
    debug_print(1, "Read %i bytes from file %s\n", (int) bytes_read, argv[1]);

    fclose(fp);
  }
  else
  {
    debug_print(1, "Argument is not a file or cannot read, assuming \"%s\" to be plaintext\n", argv[1]);

    msglen = strlen(argv[1]);
    pt  = (unsigned char *) calloc(msglen, sizeof(unsigned char));
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

    ct = hill_cipher_encrypt(ct, pt, msglen, key, block_mode, iv, iv_index); // IV and its flag are unused
    printf("Encrypted Ciphertext: "); printhex(ct, msglen + HILL_HEADER_LEN); printf("\n");

    save_bytes_to_file(output_file, ct, msglen + HILL_HEADER_LEN);
  }
  if(encipherment_mode == 2)
  {
    dpt = hill_cipher_decrypt(dpt, pt, msglen, dkey); // mode and IV is detected in encryption header
    printf("Original Ciphertext:  "); printhex(pt, msglen); printf("\n");
    printf("Decrypted Plaintext:  "); printhex(dpt, msglen - HILL_HEADER_LEN); printf("\n");
    printf("Decrypted Plaintext:  \"");
    for (i = 0; i < msglen - HILL_HEADER_LEN; ++i)
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

void init_header_struct(hillcipher_header *header) {
  header->magic[0] = 'H';
  header->magic[1] = 'C';
  header->flags = 0x00;
  header->iv = 0x00;
  header->iv_index = 0;
  header->version = 0x01;
}

void build_header_struct(hillcipher_header *header, unsigned char *data) {
  header->magic[0] = data[0];
  header->magic[1] = data[1];
  header->flags = data[2];
  header->iv = data[3];
  header->iv_index = *((unsigned int *)(&(data[4])) );
  header->version = data[8];
}

unsigned char * hill_cipher_encrypt(unsigned char *ciphertext, unsigned char *plaintext, int len, unsigned char *key, int mode, unsigned char iv, int iv_index)
{
  int i;

  // build dat fancy encryption header containing information like mode, iv or iv index, etc.
  hillcipher_header header;
  init_header_struct(&header);
  header.flags |= mode;
  if(iv_index == HILL_UNUSED && mode != HILL_MODE_ECB)
  {
    header.flags |= HILL_IV_ECB; // set no flag
    header.iv = matrix_mult_vector(key, iv); // ECB-encrypt IV if stored in header
  }
  if(iv_index != HILL_UNUSED && mode != HILL_MODE_ECB)
  {
    header.flags |= HILL_IV_TABLE; // set the left-most flag bit to 1
    header.iv_index = iv_index;
  }

  // allocate to make space for header and ciphertext result
  debug_print(1, "Allocating memory for hill cipher header and ciphertext result (%i bytes + %i bytes)\n", HILL_HEADER_LEN, len);
  ciphertext = (unsigned char *) calloc(1, len + HILL_HEADER_LEN);

  // copy header into the begining of the bytestream
  debug_print(2, "Copying header bytes to byte stream\n","");
  memcpy(ciphertext, &header, HILL_HEADER_LEN);

  switch(mode)
  {
    case HILL_MODE_ECB:
      debug_print(2, "Performing encryption of bytestream in ECB mode\n","");
      // iterate through plaintext and encrypt block-by-block without any sort of chaining..
      debug_print(2, "Calculating ciphertext at bytestream offset %i\n",HILL_HEADER_LEN);
      for (i = 0; i < len; ++i)
      {
        ciphertext[i+HILL_HEADER_LEN] = matrix_mult_vector(key, plaintext[i]);
        debug_print(2, "Encrypted character '%c' to '%c' (0x%.2X) at index %i\n",plaintext[i],ciphertext[i+HILL_HEADER_LEN],ciphertext[i+HILL_HEADER_LEN], i+HILL_HEADER_LEN);
      }
      return ciphertext;
      break;
    case HILL_MODE_CBC:
      debug_print(2, "Performing encryption of bytestream in CBC mode\n","");
      if((header.flags & HILL_HEADER_IV_MASK) == HILL_IV_TABLE)
      {
        debug_print(2, "IV source is in public nonce-generated IV table\n","");
        debug_print(2, "IV value is 0x%.2X at index %i\n", iv, header.iv_index);
      }
      else if((header.flags & HILL_HEADER_IV_MASK) == HILL_IV_ECB)
      {
        debug_print(2, "IV source is an HC-ECB encrypted byte stored in header\n","");
        debug_print(2, "IV value is 0x%.2X HC-ECB encrypted to be 0x%.2X in header\n", iv, header.iv);
      }
      else
      {
        fprintf(stderr, "ERROR: Logic failure in IV source detection. Dying...!\n","");
        exit(EXIT_FAILURE);
      }

      // main encryption routine for CBC mode with IV feedback
      for (i = 0; i < len; ++i)
      {
        if(i == 0)
        {
          ciphertext[i+HILL_HEADER_LEN] = matrix_mult_vector(key, iv ^ plaintext[i]);
          debug_print(2, "Encrypted character '%c' to '%c' (0x%.2X) at index %i (CBC'd with IV byte 0x%.2X)\n",plaintext[i],ciphertext[i+HILL_HEADER_LEN],ciphertext[i+HILL_HEADER_LEN], i+HILL_HEADER_LEN, iv);
        }
        else
        {
          ciphertext[i+HILL_HEADER_LEN] = matrix_mult_vector(key, ciphertext[i+HILL_HEADER_LEN-1] ^ plaintext[i]);
          debug_print(2, "Encrypted character '%c' to '%c' (0x%.2X) at index %i (CBC'd with prev ct byte 0x%.2X)\n",plaintext[i],ciphertext[i+HILL_HEADER_LEN],ciphertext[i+HILL_HEADER_LEN], i+HILL_HEADER_LEN, ciphertext[i+HILL_HEADER_LEN-1]);
        }
      }
      return ciphertext;
      break;
    case HILL_MODE_CFB:
      debug_print(2, "Performing encryption of bytestream in CFB mode\n","");
      printf("Detected ciphertext in CFB mode...\n");
      break;
    default:
      fprintf(stderr, "ERROR: Unknown hill cipher mode!\n","");
      exit(EXIT_FAILURE);
      break;
  }
}


unsigned char * hill_cipher_decrypt(unsigned char *plaintext, unsigned char *ciphertext, int len, unsigned char *dkey)
{
  int i;

  // build dat fancy encryption header containing information like mode, iv or iv index, etc.
  hillcipher_header header;
  build_header_struct(&header, ciphertext);

  //Attempt to read header
  if(memcmp("HC", header.magic, 2) != 0)
  {
    fprintf(stderr, "ERROR: Not an encrypted file! (Unable to find hill cipher header)\n","");
    exit(EXIT_FAILURE);
  }
  else
  {
    debug_print(2, "Found encryption header in file.\n","");
  }

  printf("Detected Hill Cipher implementation version %d\n", header.version);

  // allocate to make space for header and ciphertext result
  debug_print(1, "Allocating memory for hill cipher plaintext result (%i bytes)\n", len - HILL_HEADER_LEN);
  plaintext = (unsigned char *) calloc(1, len - HILL_HEADER_LEN);


  switch(header.flags & ~HILL_HEADER_IV_MASK) // mask out iv source flag to get mode
  {
    case HILL_MODE_ECB:
      printf("Detected ciphertext in ECB mode...\n");
      for (i = 0; i < len - HILL_HEADER_LEN; ++i)
      {
        plaintext[i] = matrix_mult_vector(dkey, ciphertext[i+HILL_HEADER_LEN]);
        debug_print(2, "Decrypted character '%c' to '%c' (0x%.2X) at data index %i\n",ciphertext[i+HILL_HEADER_LEN],plaintext[i],plaintext[i], i+HILL_HEADER_LEN);
      }
      return plaintext;
      break;
    case HILL_MODE_CBC:
      printf("Detected ciphertext in CBC mode...\n");
      debug_print(2, "Performing decryption of bytestream in CBC mode\n","");
      unsigned char iv;

      if((header.flags & HILL_HEADER_IV_MASK) == HILL_IV_TABLE)
      {
        iv = lookup_iv_in_table(header.iv_index);
        debug_print(2, "IV source is in public nonce-generated IV table\n","");
        debug_print(2, "IV value is 0x%.2X at index %i\n", iv, header.iv_index);
      }
      else if((header.flags & HILL_HEADER_IV_MASK) == HILL_IV_ECB)
      {
        iv = matrix_mult_vector(dkey, header.iv);
        debug_print(2, "IV source is an HC-ECB encrypted byte stored in header\n","");
        debug_print(2, "EC-ECB encrypted IV value is 0x%.2X in header decrypted to be 0x%.2X\n", header.iv, iv);
      }
      else
      {
        fprintf(stderr, "ERROR: Logic failure in IV source detection. Dying...!\n","");
        exit(EXIT_FAILURE);
      }

      // main encryption routine for CBC mode with IV feedback
      for (i = 0; i < len - HILL_HEADER_LEN; ++i)
      {
        if(i == 0)
        {
          plaintext[i] = iv ^ matrix_mult_vector(dkey, ciphertext[i+HILL_HEADER_LEN]);
          debug_print(2, "Decrypted character '%c' (0x%.2X) to '%c' (CBC'd with IV byte 0x%.2X)\n",ciphertext[i+HILL_HEADER_LEN],ciphertext[i+HILL_HEADER_LEN],plaintext[i], iv);
        }
        else
        {
          plaintext[i] = ciphertext[i+HILL_HEADER_LEN-1] ^ matrix_mult_vector(dkey, ciphertext[i+HILL_HEADER_LEN]);
          debug_print(2, "Decrypted character '%c' (0x%.2X) to '%c' (CBC'd with prev ct byte 0x%.2X)\n",ciphertext[i+HILL_HEADER_LEN],ciphertext[i+HILL_HEADER_LEN],plaintext[i], ciphertext[i+HILL_HEADER_LEN-1]);
        }
      }
      return plaintext;
      break;
    case HILL_MODE_CFB:
      printf("Detected ciphertext in CFB mode...\n");
      break;
    default:
      fprintf(stderr, "ERROR: Unknown hill cipher mode! (Read \"%c\" in mode field of hill cipher header)\n",ciphertext[2]);
      exit(EXIT_FAILURE);
      break;
  }
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
    debug_print(3, BYTETOBINARYPATTERN" * "BYTETOBINARYPATTERN" = %d\n", BYTETOBINARY(matrix[i]), BYTETOBINARY(vector), bit);
  }

  debug_print(3, "Result: "BYTETOBINARYPATTERN"\n", BYTETOBINARY(result));
  return result;
}


unsigned char lookup_iv_in_table(int iv_index)
{
  FILE *fp = fopen("ivtable.bin", "r+b");
  unsigned char iv;
  if(fp)
  {
    fseek(fp, IVTABLE_BITMAP_SIZE + iv_index, SEEK_SET);
    iv = (unsigned char) fgetc(fp);
    fclose(fp);
    return iv;
  }
  else
  {
    fprintf(stderr, "ERROR: cannot open IV table file...\n");
    exit(EXIT_SUCCESS);
  }
}

unsigned char consume_next_available_iv(FILE *table_fp, int *iv_index)
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
  *(iv_index) = bit_pos; // set the argument pos

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
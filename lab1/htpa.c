#define DEBUG 1
#define DEBUG_LEVEL 4
#define DISABLE_STRING_PRINT 0

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "htpa.h"


int main(int argc, char **argv) {

  // rounds default
  int htpa_rounds = 8;


  // longopts stuff
  int c; // option char
  // flag vars
  int do_help = 0;
  int do_version = 0;
  int do_encrypt = 0;
  int do_decrypt = 0;
  int do_iv = 0;
  int algorithm_mode = MODE_NOT_CHOSEN;
  char *filename = argv[0];
  unsigned char iv_bytes[EVP_MAX_IV_LENGTH] = {0}; // only for AES
  unsigned char key_bytes[EVP_MAX_KEY_LENGTH] = {0}; // only for AES

  struct option longopts[] = {
    { "algorithm",     required_argument,    NULL,         'a' },
    { "encrypt",       no_argument,          &do_encrypt,  'e' },
    { "decrypt",       no_argument,          &do_decrypt,  'd' },
    { "iv",            required_argument,    &do_iv,       'i' },
    { "rounds",        required_argument,    NULL,         'r' },
    { "help",          no_argument,          &do_help,     1 },
    { "version",       no_argument,          &do_version,  1 },
    { 0, 0, 0, 0 }
  };

  while((c = getopt_long(argc, argv, "a:edi:r:hv", longopts, NULL)) != -1 ) {
    switch(c) {
    case 'a':
      // set algothim mode
      if(strcmp(optarg, "htpa") == 0) {
        algorithm_mode = MODE_HTPA;
      } else if(strcmp(optarg, "aes") == 0) {
        algorithm_mode = MODE_AES_CBC;
      } else {
        fprintf(stderr, "ERROR: algorithm not chosen\n");
        print_help_message(argv[0]);
        exit(EXIT_FAILURE);
      }
      break;
    case 'e':
      if(algorithm_mode != MODE_AES_CBC) {
        fprintf(stderr, "WARNING: Ignoring --encrypt for HTPA.\n");
      } else {
        do_encrypt = 1;
      }
      break;
    case 'd':
      if(algorithm_mode != MODE_AES_CBC) {
        fprintf(stderr, "WARNING: Ignoring --decrypt for HTPA.\n");
      } else {
        do_decrypt = 1;
      }
      break;
    case 'r':
      if(algorithm_mode != MODE_HTPA) {
        fprintf(stderr, "WARNING: Ignoring --rounds for AES.\n");
      } else {
        htpa_rounds = atoi(optarg);
      }
      break;
    case 'i':
      if(algorithm_mode != MODE_AES_CBC) {
        fprintf(stderr, "WARNING: Ignoring --iv for HTPA.\n");
      } else {
        do_iv = 1;
        int len = strlen(optarg);
        if(len > 16) {
        memcpy(iv_bytes, optarg, 16);
        } else {
        memcpy(iv_bytes, optarg, strlen(optarg));
        }
      }
      break;
    case 'h':
      do_help = 1;
      break;
    case 'v':
      do_version = 1;
      break;
    case 0:   /* getopt_long() sets a variable, just keep going */
      break;
  #if 0
    case 1:
      break;
  #endif
    case ':':
    case '?':
    default:
      print_help_message(filename);
      exit(EXIT_SUCCESS);
      break;
    }
  }
  argc -= optind;
  argv += optind;

  // print help if flag
  if(do_help == 1) {
    print_help_message(filename);
    exit(EXIT_SUCCESS);
  }

  // print version if flag
  if(do_version == 1) {
    print_version_message();
    exit(EXIT_SUCCESS);
  }

  if(argc < 3) {
    fprintf(stderr, "ERROR: Not enough arguments\n");
    print_help_message(filename);
    exit(EXIT_FAILURE);
  }

  if(algorithm_mode == MODE_NOT_CHOSEN) {
    fprintf(stderr, "ERROR: algorithm not chosen\n");
    print_help_message(filename);
    exit(EXIT_FAILURE);
  }

  /********************************************
  * AES ALGORITHM
  ********************************************/
  if(algorithm_mode == MODE_AES_CBC) {
    int i;

    if((do_encrypt == 1 && do_decrypt == 1) || (do_encrypt != 1 && do_decrypt != 1)) {
      fprintf(stderr, "ERROR: You must specify either --encrypt *OR* --decrypt, not both or neither\n");
      exit(EXIT_FAILURE);
    }
    if(do_iv != 1) {
      fprintf(stderr, "WARNING: No --iv option, AES IV set to nulls\n");
    }
    printf("OpenSSL AES-256-CBC Algorithm Selected\n");
    if(do_encrypt == 1) {
      puts("Encryption Mode Chosen");
    }
    if(do_decrypt == 1) {
      puts("Decryption Mode Chosen");
    }

    unsigned char inbuf[CHUNK];
    unsigned char outbuf[CHUNK];
    int outlen, tmplen;

    // allocate memory for the key
    // note iv is done in getopts
    int len = strlen(argv[1]);
    if(len > 32) {
      memcpy(key_bytes, argv[1], 32);
    } else {
      memcpy(key_bytes, argv[1], strlen(argv[1]));
    }

    // fill with nulls for testing. arbitrarily large null buffer
    for (i = 0; i < CHUNK; ++i)
    {
      outbuf[i] = (unsigned char) 0x00;
      inbuf[i] = (unsigned char) 0x00;
    }

    // determine if its a file or small plaintext string
    FILE *fp = fopen(argv[0], "rb");
    size_t bytes_read;
    if(fp) {
      char buf[CHUNK];
      debug_print(3, "Opened file \"%s\" for plaintext\n", argv[0]);

      bytes_read = fread(&buf, sizeof(char), CHUNK, fp);
      debug_print(2, "Read %i bytes from file %s\n", (int) bytes_read, argv[0]);

      memcpy(inbuf, buf, bytes_read);

      fclose(fp);
    } else {
      debug_print(3, "Argument is not a file or cannot read, assuming \"%s\" to be plaintext\n", argv[0]);
      memcpy(inbuf, argv[0], strlen(argv[0]));
    }



    // OpenSSL cipher context allocs and stuff
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    // Encrypt mode:
    if(do_encrypt == 1) {
      EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key_bytes, iv_bytes);

      if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, inbuf, 128)) {
        fprintf(stderr, "EVP_EncryptUpdate() FAILED\n");
        exit(EXIT_FAILURE);
      }

      if(!EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &tmplen)) {
        fprintf(stderr, "EVP_EncryptFinal_ex() FAILED\n");
        exit(EXIT_FAILURE);
      }
      outlen += tmplen;
    }

    // Decrypt mode:
    if(do_decrypt == 1) {
      EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key_bytes, iv_bytes);

      if(!EVP_DecryptUpdate(&ctx, outbuf, &outlen, inbuf, bytes_read)) {
        fprintf(stderr, "EVP_DecryptUpdate() FAILED\n");
        exit(EXIT_FAILURE);
      }

      if(!EVP_DecryptFinal_ex(&ctx, outbuf + outlen, &tmplen)) {
        fprintf(stderr, "EVP_DecryptFinal_ex() FAILED\n");
        exit(EXIT_FAILURE);
      }
      outlen += tmplen;

    }

    // OpenSSL cipher context deallocs
    EVP_CIPHER_CTX_cleanup(&ctx);

    // open a file for ciphertext output saving
    FILE *ofp = fopen(argv[2], "wb");
    if(ofp) {
      fwrite(outbuf, outlen, 1, ofp);
      fclose(ofp);
    }
    printf("Done!\n");
  }


  /********************************************
  * HTPA ALGORITHM
  ********************************************/
  if(algorithm_mode == MODE_HTPA) {
    printf("HTPA Algorithm v.1.0 Selected\n");
    printf("%i Rounds Chosen\n", htpa_rounds);

    // create the structs for the algorithm
    htpa_bytes plaintext;  htpa_bytes *plaintext_ptr  = &plaintext;
    htpa_bytes key;        htpa_bytes *key_ptr        = &key;
    htpa_bytes ciphertext; htpa_bytes *ciphertext_ptr = &ciphertext;

    // attempt to open a file, if error assume to be message string
    FILE *fp = fopen(argv[0], "rb");
    if(fp) {
      debug_print(3, "Opened file \"%s\" for plaintext\n", argv[0]);
      char buf[CHUNK];
      size_t bytes_read;

      bytes_read = fread(&buf, sizeof(char), CHUNK, fp);
      debug_print(2, "Read %i bytes from file %s\n", (int) bytes_read, argv[0]);

      plaintext.bytes = (unsigned char *) calloc(bytes_read, sizeof(unsigned char));
      memcpy(plaintext.bytes, buf, bytes_read);
      plaintext.len = bytes_read;

      fclose(fp);
    } else {
      debug_print(3, "Argument is not a file or cannot read, assuming \"%s\" to be plaintext\n", argv[0]);
      plaintext.bytes = (unsigned char *) calloc(strlen(argv[0]), sizeof(unsigned char));
      memcpy(plaintext.bytes, argv[0], strlen(argv[0]));
      plaintext.len = strlen(argv[0]);
    }

    // allocate memory for the key
    key.bytes = (unsigned char *) calloc(KEY_BYTE_LEN, sizeof(unsigned char));
    // Ensure that it copies a max length of KEY_BYTE_LEN
    if(strlen(argv[1]) < KEY_BYTE_LEN) {
      memcpy(key.bytes, argv[1], strlen(argv[1]));
    } else {
      memcpy(key.bytes, argv[1], KEY_BYTE_LEN);
    }
    key.len = KEY_BYTE_LEN;

    // perform the HTPA algorithm and save to a file
    htpa_algorithm(ciphertext_ptr, plaintext_ptr, key_ptr, htpa_rounds);

    // open a file for ciphertext output saving
    FILE *ofp = fopen(argv[2], "wb");
    if(ofp) {
      fwrite(ciphertext_ptr->bytes, ciphertext_ptr->len, 1, ofp);
      fclose(ofp);
    }

    // free memory used in byte strings
    free(ciphertext_ptr->bytes); ciphertext_ptr->bytes = NULL;
    free(key_ptr->bytes); key_ptr->bytes = NULL;
    free(plaintext_ptr->bytes); plaintext_ptr->bytes = NULL;
  }

  exit(EXIT_SUCCESS);
}


htpa_bytes * htpa_algorithm(htpa_bytes *ciphertext, htpa_bytes *plaintext, htpa_bytes *key, int rounds) {
  int i; int j; char str_buf[CHUNK] = { 0x00 };

  debug_print(4, "HTPA Block Length:       %i bytes (%i bits)\n", BLOCK_BYTE_LEN, BLOCK_LEN);
  debug_print(4, "HTPA Block-Half Length:  %i bytes (%i bits)\n", BLOCK_BYTE_HALF_LEN, BLOCK_HALF_LEN);
  debug_print(4, "HTPA Key Length:         %i bytes (%i bits)\n", KEY_BYTE_LEN, KEY_LEN);
  debug_print(4, "HTPA Round Key Length:   %i bytes (%i bits)\n", ROUND_BYTE_KEY_LEN, ROUND_KEY_LEN);

  printf("HTPA Key   "); fprint_bytes_hex(stdout, key);
  printf("HTPA Key   "); fprint_bytes_str(stdout, key);


  unsigned char str[KEY_BYTE_LEN];
  unsigned char str2[ROUND_BYTE_KEY_LEN];

  for (i = 0; i < KEY_BYTE_LEN; ++i) {
    str[i] = key->bytes[i];
  }

  for (i = 0; i < ROUND_BYTE_KEY_LEN; ++i) {
    debug_print(4, "START:    "BYTETOBINARYPATTERN" \n", BYTETOBINARY(str[i]));

    // shift-left entire byte by i bits because of previous byte taking i bits of this one
    str[i] = str[i] << i;
    debug_print(4, "SHIFT LF: "BYTETOBINARYPATTERN" (Shift Left %i Bits)\n", BYTETOBINARY(str[i]), i);

    // Remove/Mask out the last i+1 bits (i because of previous + 1 new bit to be removed)
    str[i] = str[i] >> i+1;
    str[i] = str[i] << i+1;
    debug_print(4, "REM LAST: "BYTETOBINARYPATTERN" (Moved Right-Left %i Bits)\n", BYTETOBINARY(str[i]), (i+1));

    // shift next byte's first-most i+1 bits to the right-most (position 8)
    unsigned char temp = str[i+1] >> (8 - (i+1));
    debug_print(4, "NXT SHFT: "BYTETOBINARYPATTERN" (Shift Right %i Bits)\n", BYTETOBINARY(temp), (8 - (i+1)));

    // combine/bitwise-OR the result
    str2[i] = str[i] | temp;
    debug_print(4, "BOR BOTH: "BYTETOBINARYPATTERN" \n", BYTETOBINARY(str2[i]));
    debug_print(4, "---------------%s", "\n");
  }

  for (i = 0; i < ROUND_BYTE_KEY_LEN; ++i) {
    sprintf(str_buf, "%s0x%.2X ", str_buf, str2[i]);
  }
  debug_print(2, "Key Schedule: %s\n", str_buf);


  printf("Plaintext  "); fprint_bytes_hex(stdout, plaintext);
  printf("Plaintext  "); fprint_bytes_str(stdout, plaintext);

  debug_print(1, "Splitting plaintext into blocks%s", "\n");
  htpa_blocks_array *plaintext_blocks = split_into_blocks(plaintext);


  ciphertext->len = BLOCK_BYTE_LEN * calc_blocks_for_bytes(plaintext);
  ciphertext->bytes = (unsigned char *) calloc(ciphertext->len, sizeof(unsigned char));
  debug_print(3, "Allocated memory for for %i bytes of ciphertext\n", ciphertext->len);
  unsigned char *cursor = ciphertext->bytes;

  for (i = 0; i < plaintext_blocks->size; ++i) {
    debug_print(1, "Block %i of %i: Encipherment algorithm starting!\n", i+1, plaintext_blocks->size);
    for (j = 0; j < rounds; ++j) {
      if(j+1 == rounds) {
        debug_print(3, "Block %i of %i: HTPA Round %i of %i: Final round! Not swapping block halves\n", i+1, plaintext_blocks->size, j+1, rounds);
        htpa_final_round(plaintext_blocks->blocks[i]);
      } else {
        htpa_round(plaintext_blocks->blocks[i]);
      }

      char *blck_txt = get_bytes_str(plaintext_blocks->blocks[i]);
      char *blck_hex = get_bytes_hex(plaintext_blocks->blocks[i]);
      debug_print(3, "Block %i of %i: HTPA Round %i of %i: \"%s\"\n", i+1, plaintext_blocks->size, j+1, rounds, blck_txt);
      debug_print(3, "Block %i of %i: HTPA Round %i of %i: %s\n", i+1, plaintext_blocks->size, j+1, rounds, blck_hex);
      free(blck_txt); blck_txt = NULL;
      free(blck_hex); blck_hex = NULL;
    }
    debug_print(2, "Block %i of %i: copying bytes into final ciphertext byte array\n", i+1, plaintext_blocks->size);
    memcpy(cursor, plaintext_blocks->blocks[i]->bytes, BLOCK_BYTE_LEN);
    debug_print(3, "Block %i of %i: Moved cursor to array position %i\n", (i+1), plaintext_blocks->size, (i+1)*BLOCK_BYTE_LEN);
    cursor = cursor + BLOCK_BYTE_LEN;
  }

  printf("Ciphertext "); fprint_bytes_hex(stdout, ciphertext);
  printf("Ciphertext "); fprint_bytes_str(stdout, ciphertext);

  free_blocks_array(plaintext_blocks);
  return ciphertext;
}

void printf_blocks_array(htpa_blocks_array * array_ptr) {
  int i;
  for (i = 0; i < array_ptr->size; ++i)
  {
    printf("Block %i: ", i+1); fprint_bytes_str(stdout, array_ptr->blocks[i]);
    printf("Block %i: ", i+1); fprint_bytes_hex(stdout, array_ptr->blocks[i]);
  }
}

void fprint_bytes_hex(FILE *stream, htpa_bytes * bytes_ptr) {
  char * bytes_hex_str = get_bytes_hex(bytes_ptr);
  fprintf(stream, "( HEX ): \"%s\" (%i bytes, %i bits)\n", bytes_hex_str, bytes_ptr->len, calc_bits(bytes_ptr));
  free(bytes_hex_str);
  bytes_hex_str = NULL;
}

void fprint_bytes_str(FILE *stream, htpa_bytes * bytes_ptr) {
  char * bytes_str = get_bytes_str(bytes_ptr);
  fprintf(stream, "(ASCII): \"%s\" (%i bytes, %i bits)\n", bytes_str, bytes_ptr->len, calc_bits(bytes_ptr));
  free(bytes_str);
  bytes_str = NULL;
}

char * get_bytes_hex(htpa_bytes * bytes_ptr) {
  int strsize = bytes_ptr->len * 3 - 1 + 1;
  char * str = (char *) malloc(strsize); // -1 for missing space and +1 for str nullbyte
  int i;
  for (i = 0; i < strsize; ++i) { str[i] = '\0'; } // initialize string space of null

  for (i = 0; i < bytes_ptr->len; ++i) {
    if (i > 0) sprintf(str, "%s ", str);
    sprintf(str, "%s%.2X", str, bytes_ptr->bytes[i]);
  }

  return str;
}
char * get_bytes_str(htpa_bytes * bytes_ptr) {
  if(DISABLE_STRING_PRINT) {
    return NULL;
  }

  int strsize = bytes_ptr->len + 1;
  char * str = (char *) malloc(strsize);
  int i;
  for (i = 0; i < strsize; ++i) { str[i] = '\0'; } // initialize string space of null

  for (i = 0; i < bytes_ptr->len; ++i) {
    sprintf(str, "%s%c", str, (char) bytes_ptr->bytes[i]);
  }

  return str;
}

int calc_bits(htpa_bytes * bytes_ptr) {
  return bytes_ptr->len * CHAR_BIT;
}

int calc_blocks_for_bytes(htpa_bytes * bytes_ptr) {
  int blocks = 0;
  int i;
  for (i = 0; i < bytes_ptr->len; ++i) {
    if (i % BLOCK_BYTE_LEN == 0) {
      blocks++;
    }
  }
  debug_print(1, "Number of blocks: %i (%i bytes, %i bits)\n", blocks, blocks * BLOCK_BYTE_LEN, blocks * BLOCK_LEN);
  return blocks;
}

htpa_blocks_array * split_into_blocks(htpa_bytes * bytes_ptr) {
  int blocks_total_num = calc_blocks_for_bytes(bytes_ptr);
  int block_num = 0;
  unsigned char * cursor = bytes_ptr->bytes; // a cursor to traverse the index of the actual bytes array

  debug_print(3, "Allocating memory for blocks array struct of size %i\n", blocks_total_num);

  // Allocate memory for a pointer to the array struct
  htpa_blocks_array *byte_streams_array = (htpa_blocks_array *) malloc(sizeof(htpa_blocks_array));
  debug_print(4, "Allocated memory for blocks array structure.%s","\n");

  // Allocate memory for blocks array pointer and each block struct
  byte_streams_array->size = blocks_total_num;
  byte_streams_array->blocks = (htpa_bytes **) malloc(sizeof(htpa_bytes *) * blocks_total_num);
  debug_print(4, "Allocated memory for %i block pointers for blocks array struct.\n", blocks_total_num);
  int i;
  for (i = 0; i < blocks_total_num; ++i)
  {
    byte_streams_array->blocks[i] = (htpa_bytes *) malloc(sizeof(htpa_bytes));
    byte_streams_array->blocks[i]->len = BLOCK_BYTE_LEN;
    // calloc() used because it fills the array with nulls. Useful because last block, if short, will leave those nulls as padding
    byte_streams_array->blocks[i]->bytes = (unsigned char *) calloc(BLOCK_BYTE_LEN, sizeof(unsigned char));
    debug_print(4, "Allocated memory for block %i of %i struct for array.\n", i+1, blocks_total_num);
  }

  // iterate through the long bytes_ptr byte stream and break it into blocks
  for (i = 0; i < bytes_ptr->len; ++i) {
    int remaining_bytes = bytes_ptr->len - i;
    if (i % BLOCK_BYTE_LEN == 0) {
      ++block_num;
      if(remaining_bytes < BLOCK_BYTE_LEN) {
        // this / last block is short and needs "padding". Only copy the remaining bytes, leaving the rest of the block filled with NULLs
        int byte_pad_size = BLOCK_BYTE_LEN - remaining_bytes;
        debug_print(2, "Block %i of %i is short %i bytes (%i bits)! memcpy'ing only %i bytes\n", block_num, blocks_total_num, byte_pad_size, byte_pad_size * CHAR_BIT, remaining_bytes);
        memcpy(byte_streams_array->blocks[block_num-1]->bytes, cursor, remaining_bytes);
      } else {
        memcpy(byte_streams_array->blocks[block_num-1]->bytes, cursor, BLOCK_BYTE_LEN);
      }

      char *blck_txt = get_bytes_str(byte_streams_array->blocks[block_num-1]);
      char *blck_hex = get_bytes_hex(byte_streams_array->blocks[block_num-1]);
      debug_print(2, "Block %i of %i: \"%s\"\n", block_num, blocks_total_num, blck_txt);
      debug_print(2, "Block %i of %i: \"%s\"\n", block_num, blocks_total_num, blck_hex);
      free(blck_txt); blck_txt = NULL;
      free(blck_hex); blck_hex = NULL;

      // offset cursor to next block position for copying
      cursor = cursor + BLOCK_BYTE_LEN;
    }
  }

  return byte_streams_array;
}

void free_blocks_array(htpa_blocks_array *array_ptr) {
  debug_print(3, "Deallocating memory for blocks array struct of size %i.\n", array_ptr->size);
  int i;
  for (i = 0; i < array_ptr->size; ++i)
  {
    free(array_ptr->blocks[i]->bytes); array_ptr->blocks[i]->bytes = NULL;
    free(array_ptr->blocks[i]); array_ptr->blocks[i] = NULL;
    debug_print(4, "Freed block %i of %i in array\n", (i+1), array_ptr->size);
  }
  free(array_ptr->blocks); array_ptr->blocks = NULL;
  debug_print(4, "Freed blocks pointer%s", "\n");
  free(array_ptr); array_ptr = NULL;
  debug_print(4, "Freed blocks array!%s", "\n");
}

void pad_bytes(htpa_bytes * bytes_ptr) {
  int new_size = bytes_ptr->len + (BLOCK_BYTE_LEN - (bytes_ptr->len % BLOCK_BYTE_LEN));
  debug_print(3, "Resizing byte stream to a total of %i bytes (%i bits)\n", new_size, new_size * CHAR_BIT);
  bytes_ptr->bytes = (unsigned char *) realloc(bytes_ptr->bytes, new_size * sizeof(unsigned char));
  bytes_ptr->len = new_size;
}

unsigned char subbyte(unsigned char byte) {
  return sbox[byte];
}

void htpa_round(htpa_bytes *block) {
  int i;
  unsigned char * left_index = block->bytes;
  unsigned char * right_index = left_index + BLOCK_BYTE_HALF_LEN;

  htpa_bytes tmp_left_side;  tmp_left_side.len  = BLOCK_BYTE_HALF_LEN;
  htpa_bytes tmp_right_side; tmp_right_side.len = BLOCK_BYTE_HALF_LEN;
  htpa_bytes round_key;      round_key.len      = ROUND_BYTE_KEY_LEN;

  tmp_left_side.bytes  = (unsigned char *) calloc(BLOCK_BYTE_HALF_LEN, sizeof(unsigned char));
  tmp_right_side.bytes = (unsigned char *) calloc(BLOCK_BYTE_HALF_LEN, sizeof(unsigned char));
  // round_key.bytes      = (unsigned char *) calloc(ROUND_BYTE_KEY_LEN,  sizeof(unsigned char));
  round_key.bytes = (unsigned char *) "AAAAAAAA";
  debug_print(4, "Allocated byte stream structs for halves and round key%s", "\n");

  memcpy(tmp_left_side.bytes,  left_index,  BLOCK_BYTE_HALF_LEN);
  memcpy(tmp_right_side.bytes, right_index, BLOCK_BYTE_HALF_LEN);
  debug_print(4, "Copied block halves into temp arrays%s", "\n");

  // copy right-side into left-side of block
  memcpy(left_index, right_index, BLOCK_BYTE_HALF_LEN);
  debug_print(4, "Copied right-side half into left-side half of block%s", "\n");

  // this tmp_left_side variable will be the new "right-side" once it's XOR'd with the old right-side's function output
  // debug_print(3, "Sending right-side and round key into round function%s", "\n");
  // htpa_round_function(&tmp_right_side, &round_key);
  for (i = 0; i < BLOCK_BYTE_HALF_LEN; ++i) {
    tmp_left_side.bytes[i] = tmp_right_side.bytes[i] ^ tmp_left_side.bytes[i];
  }
  debug_print(3, "XOR'd the round function's output with left-ride%s", "\n");

  // copy newly calculated right-side back into the block
  memcpy(right_index, tmp_left_side.bytes, BLOCK_BYTE_HALF_LEN);
  debug_print(4, "Copied left-side half into right-side half of block%s", "\n");
  debug_print(3, "Completed fiestal swap for round!%s", "\n");

  free(tmp_left_side.bytes);
  free(tmp_right_side.bytes);
  // free(round_key.bytes);
  debug_print(4, "Freed byte stream structs for halves and round key%s", "\n");
}

void htpa_final_round(htpa_bytes *block) {
  int i;
  unsigned char * left_index = block->bytes;
  unsigned char * right_index = left_index + BLOCK_BYTE_HALF_LEN;

  htpa_bytes round_key;      round_key.len      = ROUND_BYTE_KEY_LEN;
  round_key.bytes = (unsigned char *) calloc(ROUND_BYTE_KEY_LEN,  sizeof(unsigned char));

  htpa_bytes tmp_right_side; tmp_right_side.len = BLOCK_BYTE_HALF_LEN;
  tmp_right_side.bytes = (unsigned char *) calloc(BLOCK_BYTE_HALF_LEN, sizeof(unsigned char));
  memcpy(tmp_right_side.bytes, right_index, BLOCK_BYTE_HALF_LEN);

  // this tmp_left_side variable will be the new "right-side" once it's XOR'd with the old right-side's function output
  // debug_print(3, "Sending right-side and round key into round function%s", "\n");
  // htpa_round_function(&tmp_right_side, &round_key);
  for (i = 0; i < BLOCK_BYTE_HALF_LEN; ++i) {
    left_index[i] = tmp_right_side.bytes[i] ^ left_index[i];
  }
  debug_print(3, "XOR'd the round function's output with left-ride%s", "\n");

  memcpy(right_index, tmp_right_side.bytes, BLOCK_BYTE_HALF_LEN);

  free(tmp_right_side.bytes);
  free(round_key.bytes);
  debug_print(4, "Freed byte stream structs for round key%s", "\n");
}

void htpa_round_function(htpa_bytes *block_half, htpa_bytes *round_key) {
  int i;
  for (i = 0; i < BLOCK_BYTE_HALF_LEN; ++i) {
    block_half->bytes[i] = block_half->bytes[i] ^ round_key->bytes[i];
  }
  debug_print(3, "XOR'd the right-side with round key%s", "\n");
  for (i = 0; i < BLOCK_BYTE_HALF_LEN; ++i) {
    block_half->bytes[i] = subbyte(block_half->bytes[i]);
  }
  debug_print(3, "Substituted bytes!%s", "\n");
}

void print_version_message() {
  printf("CPS713 Lab 1 Program v.1.0\n");
  printf("by Justin B. & Jonathan K.\n\n");

  puts("Copyright (C) 2013 Justin Bull, Jonathan Kwan");
  puts("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>");
  puts("This is free software: you are free to change and redistribute it.");
  puts("There is NO WARRANTY, to the extent permitted by law.");
}

void print_help_message(char *name) {
  printf("Usage: %s [options] filename_or_message key output_file\n\n", name);

  printf("CPS713 Lab1 Program v.1.0\n");
  printf("by Justin B. & Jonathan K.\n\n");

  puts("Options:\n");

  puts(" -a, --algorithm [htpa|aes]   run the program using ALGO algorithm 'htpa' or 'aes'");
  puts(" -e, --encrypt                encrypt the plaintext in filename_or_message (AES only)");
  puts(" -d, --decrypt                decrypt the ciphertext in filename_or_message (AES only)");
  puts(" -i, --iv IV                  use AES with IV as initialization vector (AES only)");
  puts(" -r, --rounds N               perform N rounds of ALGO (HTPA only)");
  puts(" -h, --help                   display this help and exit");
  puts(" -v, --version                display version information and exit\n");

  puts("Options '-e' and '-d' contradict each other and at least one is required.\nIf both options are either present or missing, the program will exit.\n");

  puts("Report bugs to: <cps713-lab1@justinbull.ca>");
}
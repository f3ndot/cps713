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
#include <time.h>
#include "lab2.h"

static unsigned long int next = 1;
int lab2_rand(void) // RAND_MAX assumed to be 32767
{
  next = next * 1103515245 + 12345;
  return (unsigned int)(next/65536) % 32768;
}
unsigned int lab2_srand(unsigned int seed)
{
  next = seed;
  return next;
}

int main(int argc, char *argv[])
{
  int i = 0;
  char *progname = argv[0];
  if (argc < 2)
  {
    print_help(progname);
    exit(EXIT_FAILURE);
  }
  int maxSamples = atoi(argv[1]);

  int initSeed = lab2_srand(time(NULL));
  debug_print(1, "Going through %i samples of C-based rand()\n", maxSamples);
  debug_print(1, "Using initial seed value: %i\n", initSeed);

  int *storageArray;
  storageArray = (int *) malloc(sizeof(int) * maxSamples);
  for( i = 0; i < maxSamples; i++)
  {
    int x = lab2_rand();
    debug_print(1, "byte %i of %i: 0x%.2X (%i)\n", i+1, maxSamples, x, x);
    storageArray[i] = x;
  }
  for( i = 0; i < maxSamples; i++)
  {
    printf(BYTETOBINARYPATTERN, BYTETOBINARY(storageArray[i]));
  }

  free(storageArray); storageArray = NULL;
  exit(EXIT_SUCCESS);
}

void print_help(char *prgnme) {
  printf("Usage: %s bytelength\n\n", prgnme);
  printf(" ** An ASCII binary stream will print to stdout for use with STS ** \n\n");
}
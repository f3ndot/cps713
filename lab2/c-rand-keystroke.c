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
#include <sys/time.h>
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
  unsigned long initSeed = 0;
  char *progname = argv[0];
  if (argc < 2)
  {
    print_help(progname);
    exit(EXIT_FAILURE);
  }
  int maxSamples = atoi(argv[1]);

  struct timeval tv_init;
  struct timeval tv;
  gettimeofday(&tv_init, NULL);

  int numOfKeystrokes = 10;
  if (argc >= 3)
  {
    numOfKeystrokes = atoi(argv[2]);
  }

  debug_print(2, "UINT_MAX is %lu\n", (unsigned long) UINT_MAX);
  for (i = 0; i < numOfKeystrokes; ++i)
  {
    int tmp = getchar();
    gettimeofday(&tv, NULL);

    debug_print(1, "Got char %i at usec %i\n", tmp, tv.tv_usec);
    initSeed = ((initSeed ^ tv.tv_usec) * tmp) % UINT_MAX;
    debug_print(1, "Seed currently %lu at round %i/10\n", initSeed, i+1);
  }

  debug_print(1, "Going through %i samples of C-based rand()\n", maxSamples);
  debug_print(1, "Using initial seed value: %lu\n", initSeed);
  lab2_srand((unsigned int) initSeed);

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
  printf("Usage: %s bytelength [keystrokes]\n\n", prgnme);
  printf(" ** An ASCII binary stream will print to stdout for use with STS ** \n");
  printf(" ** If [keystrokes] is empty, it'll default to 10 chars ** \n\n");
}
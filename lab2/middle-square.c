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
#include <time.h>
#include "lab2.h"

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

  // check for seed
  int initSeed = 0;
  if(argc >= 3)
  {
    initSeed = atoi(argv[2]);
    debug_print(1, "Initial seed of %i provided!\n", initSeed);
  }
  else
  {
    initSeed = 1000 + (time(NULL) % 9000);
    debug_print(1, "Using time(NULL) to obtain 4-digit seed\n", "");
  }

  debug_print(1, "Going through %i samples of middle square\n", maxSamples);
  debug_print(1, "Using initial seed value: %i\n", initSeed);

  int x = initSeed;
  int newSeed;
  int *storageArray;
  storageArray = (int *) malloc(sizeof(int) * maxSamples);
  for( i = 0; i < maxSamples; i++)
  {
    // take previous seed or initial number
    newSeed = x * x;
    debug_print(2, "%i * %i = %i\n", x, x, newSeed);

    // select the middle four digits as output and next seed
    int oldSeed = newSeed;
    newSeed = (newSeed / 100) % 10000;
    debug_print(2, "(%i / 100) %% 10000 = %i\n", oldSeed, newSeed);

    // set the new seed as previous seed for next iteration
    x = newSeed;

    // store as output as well
    storageArray[i] = x;

    debug_print(1, "byte %i of %i: 0x%.2X (%i)\n", i+1, maxSamples, x, x);
  }
  for( i = 0; i < maxSamples; i++)
  {
    printf(BYTETOBINARYPATTERN, BYTETOBINARY(storageArray[i]));
  }

  free(storageArray); storageArray = NULL;
  exit(EXIT_SUCCESS);
}

void print_help(char *prgnme) {
  printf("Usage: %s bytelength [seed]\n\n", prgnme);
  printf(" ** Omitting [seed] will cause the program to use time(NULL) ** \n");
  printf(" ** An ASCII binary stream will print to stdout for use with STS ** \n\n");
}
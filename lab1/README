Hello Professor or TAs,

To compile the assignment simply type make or run the following:

gcc htpa.c -lssl -lcrypto -o htpa


To perform AES encryption:
./htpa -a aes -i initialization_vector -e filename_or_message key ciphertext_file

To perform AES decryption:
./htpa -a aes -i initialization_vector -e ciphertext_file key plaintext_file

To perform HTPA encryption/decryption:
./htpa -a htpa filename_or_message key outputfile_file



To see various options and explanations type:
./htpa --help

Which will yield:

    Usage: ./htpa [options] filename_or_message key output_file

    CPS713 Lab1 Program v.1.0
    by Justin B. & Jonathan K.

    Options:

     -a, --algorithm [htpa|aes]   run the program using ALGO algorithm 'htpa' or 'aes'
     -e, --encrypt                encrypt the plaintext in filename_or_message (AES only)
     -d, --decrypt                decrypt the ciphertext in filename_or_message (AES only)
     -i, --iv IV                  use AES with IV as initialization vector (AES only)
     -r, --rounds N               perform N rounds of ALGO (HTPA only)
     -h, --help                   display this help and exit
     -v, --version                display version information and exit

    Options '-e' and '-d' contradict each other and at least one is required.
    If both options are either present or missing, the program will exit.

    Report bugs to: <cps713-lab1@justinbull.ca>



*NOTE:*
You can set the level of debug or turn it on and off in the DEBUG_LEVEL and DEBUG defines in htpa.c accordingly.
If a DEBUG_LEVEL is not set, it'll default to "1".

*NOTE:*
It wasn't until very late on Sunday night did I realize my implementation of the bitwise permutations were completely backward (I interpreted bit postion 8 as the right-most bit). As a result, HTPA algorithm is broken in its application. Inspection of the source reveals 90% of the code is in perfect functioning order. I was able to fix the key schedule PC-X in time, however.

Team:
Justin Bull 500355958
Jonathan Kwan 500342079

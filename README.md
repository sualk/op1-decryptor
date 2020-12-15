# Firmware decryption tool for OP-1

This tool allows the decryption of the OP-1 firmware. Especially the file `OP1_vdk.ldr`.
In that file every boot stream block with the flag `BFLAG_CALLBACK` is encrpyted using the XTEA algorithm.
For every 24 byte block only the first 8 byte are encrypted and the remaining 16 bytes are unencrypted.

## Compilation
Compile with `gcc`

    gcc -o decrypt decrypt.c

## Usage
Key, input file and output file needs to be provided as parameters

    decrypt [key] [input] [output]

### Key
The key is a 16 byte in length and must be provided as 32 character hexadecimal string on the command line.

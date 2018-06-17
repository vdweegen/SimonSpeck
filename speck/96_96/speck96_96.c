/**
* speck96_96.c - Speck implementation
*
* Key Size:   96
* Block Size: 96
*
* Author: Cas van der Weegen <cas@vdweegen.com>
*
* Copyright (c) 2017 Cas van der Weegen
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "speck96_96.h"

const uint8_t rotation_alpha = 8;
const uint8_t rotation_beta = 3;
const uint8_t key_size = 2; // key_size = 96 / word_size
const uint8_t word_size = 48; // word_size = block_size / 2
const uint8_t bytes = 6; // bytes = word_size / 8
const uint8_t rounds = 28;
const uint64_t mod_mask = 0x00FFFFFFFFFFFF;

#define rotate_right(x, r) ((x >> r) | (x << (word_size - r)))
#define rotate_left(x, r) ((x << r) | (x >> (word_size - r)))

void expand_speck(uint8_t *key, uint8_t *key_schedule)
{
    uint8_t i;
    uint64_t keys[4] = {};

    for (i = 0; i < key_size; i++)
    {
        memcpy(&keys[i], key + (bytes * i), bytes);
    }

    memcpy(key_schedule, &keys[0], bytes);

    uint64_t x,y;
    //printf("Subkeys 3:%04x  2:%04x  1:%04x  0:%04x  \n",keys[3],keys[2],keys[1],keys[0]);

    for (i = 0; i < rounds; i++) {
        x = rotate_right(keys[1], rotation_alpha) & mod_mask;
        //printf("Check rotate: %04x %04x\n",keys[1], x);
        x = (x + keys[0]) & mod_mask;
        //printf("Check Add: %04x\n",x);
        x = (x ^ i) & mod_mask;
        //printf("New X: %x\n",x);
        y = rotate_left(keys[0], rotation_beta) & mod_mask;
        //printf("Check rotate: %04x %04x\n",keys[0], y);
        y = y ^ x;
        //printf("New Y: %04x\n",y);
        keys[0] = y;

        for (int i = 1; i < (key_size - 1); i++)
        {
            keys[i] = keys[i + 1];
        }

        keys[key_size - 1] = x;

        //printf("Subkeys 3:%04x  2:%04x  1:%04x  0:%04x  \n",keys[3],keys[2],keys[1],keys[0]);

        memcpy(key_schedule + (bytes * (i+1)), &keys[0], bytes);
    }
}

void encrypt_speck_96_96(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
  uint64_t y,x;
  memcpy(&y, plaintext, bytes);
  memcpy(&x, plaintext + bytes, bytes);
  uint64_t round_key;

  x = x & mod_mask;
  y = y & mod_mask;

  for(uint8_t i = 0; i < rounds; i++) {
      memcpy(&round_key, key_schedule + (bytes * i), bytes);
      round_key = round_key & mod_mask;
      x = rotate_right(x, rotation_alpha) & mod_mask;
      // printf("[ROR X] %04x ",x);
      x = (x + y) & mod_mask;
      // printf("[ADD X] %04x ",x);
      x = (x ^ round_key) & mod_mask;
      // printf("[XOR X] %04x ",x);
      y = rotate_left(y, rotation_beta) & mod_mask;
      // printf("[ROL Y] %04x ",y);
      y = (y ^ x) & mod_mask;
      // printf("[XOR Y] %04x \n",y);
  }
  // printf("\n");
  // Assemble Ciphertext Output Array
  bytes6_t *k = (bytes6_t *)ciphertext;
  *k = *(bytes6_t *)&y;
  k += 1;
  *k = *(bytes6_t *)&x;
}

void decrypt_speck_96_96(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
  uint64_t y,x;
  memcpy(&y, ciphertext, bytes);
  memcpy(&x, ciphertext + bytes, bytes);
  uint64_t round_key;

  x = x & mod_mask;
  y = y & mod_mask;

  for(uint8_t i = 0; i < rounds; i++) {
      memcpy(&round_key, key_schedule + (bytes * (rounds - 1 - i)), bytes);
      round_key = round_key & mod_mask;
      y = (y ^ x) & mod_mask;
      // printf("[XOR Y] %04x ",y);
      y = rotate_right(y, rotation_beta) & mod_mask;
      // printf("[ROR Y] %04x ",y);
      x = (x ^ round_key) & mod_mask;
      // printf("[XOR X] %04x ",x);
      x = (x - y) & mod_mask;
      // printf("[ADD X] %04x ",x);
      x = rotate_left(x, rotation_alpha) & mod_mask;
      // printf("[ROL X] %04x \n",x);
  }
  // printf("\n");
  // Assemble Ciphertext Output Array
  bytes6_t *k = (bytes6_t *)plaintext;
  *k = *(bytes6_t *) & y;
  k += 1;
  *k = *(bytes6_t *) & x;
}

int main(void)
{
    printf("Test Speck 96/96\n");
    uint8_t key_schedule[6*rounds];
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    uint8_t encryption_key[] = {0x00,0x01,0x02,0x08,0x09,0x0A,0x10,0x11,0x12,0x18,0x19,0x1a};
    uint8_t plaintext[] = {0x20, 0x75, 0x73, 0x61, 0x67, 0x65, 0x2c, 0x20, 0x68, 0x6f, 0x77, 0x65};

    // printf("Test Speck 96/96 Expanding\n");
    expand_speck(encryption_key, key_schedule);
    // printf("Test Speck 96/96 Encrypting\n");
    encrypt_speck_96_96(key_schedule, plaintext, ciphertext);
    // printf("Test Speck 96/96 Decryption\n");
    decrypt_speck_96_96(key_schedule, decrypted, ciphertext);

    printf("Plaintext %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x \n",plaintext[0],plaintext[1],plaintext[2],plaintext[3],plaintext[4],plaintext[5],plaintext[6],plaintext[7],plaintext[8],plaintext[9],plaintext[10],plaintext[11]);
    printf("Encrypted %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x \n",ciphertext[0],ciphertext[1],ciphertext[2],ciphertext[3],ciphertext[4],ciphertext[5],ciphertext[6],ciphertext[7],ciphertext[8],ciphertext[9],ciphertext[10],ciphertext[11]);
    printf("Decrypted %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x \n",decrypted[0],decrypted[1],decrypted[2],decrypted[3],decrypted[4],decrypted[5],decrypted[6],decrypted[7],decrypted[8],decrypted[9],decrypted[10],decrypted[11]);
    return 0;
}

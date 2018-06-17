/**
* simon128_128.c - Simon implementation
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

const uint8_t key_size = 2; // key_size % word_size
const uint8_t word_size = 64; // block_size % 2
const uint8_t bytes = 8; // word_size % 8
const uint8_t rounds = 68;
const uint64_t z_sequence = 0b0011001101101001111110001000010100011001001011000000111011110101;

#define ULLONG_MAX 18446744073709551615ULL

#define shift_left(x, r) ((x << r) | (x >> (word_size - r)))
#define shift_right(x, r) (x >> r) | ((x & ((1 << r) - 1)) << (word_size - r))

void expand_simon_128_128(uint8_t *key, uint8_t *key_schedule)
{
  uint64_t mod_mask = ULLONG_MAX;
  uint8_t i;
  uint64_t keys[4] = {};

  for (i = 0; i < key_size; i++)
  {
    memcpy(&keys[i], key + (bytes * i), bytes);
  }

  memcpy(key_schedule, &keys[0], bytes);

  uint64_t c = 0xfffffffffffffffc;
  uint64_t x,y;

  for (i = 0; i < rounds; i++) {
    x = shift_right(keys[key_size - 1], 3) & mod_mask;
    // x = x ^ keys[1]; // ONLY if key_size = 4
    y = shift_right(x,1) & mod_mask;
    x = x ^ keys[0] & mod_mask;
    x = x ^ y;
    y = (c ^ ((z_sequence >> (i % 62)) & 1)) & mod_mask;
    x = x ^ y;

    for (uint8_t i = 0; i < (key_size - 1); i++) {
      keys[i] = keys[i+1];
    }

    keys[key_size -1] = x & (ULLONG_MAX >> (64 - word_size));
    memcpy(key_schedule + (bytes * (i+1)), &keys[0], bytes);
  }
}

void encrypt_simon_128_128(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
  uint64_t mod_mask = ULLONG_MAX;
  uint64_t y = *(uint64_t *)plaintext;
  uint64_t x = *(((uint64_t *)plaintext) + 1);
  uint64_t *k = (uint64_t *)key_schedule;
  uint64_t *w = (uint64_t *)ciphertext;
  uint64_t tmp;

  for(int i = 0; i < rounds; i++) {
    tmp = shift_left(x, 1) & mod_mask;
    tmp = (tmp & shift_left(x, 8)) & mod_mask;
    tmp = (tmp ^ y) & mod_mask;
    tmp = (tmp ^ shift_left(x, 2)) & mod_mask;
    y = x; // Feistell Cross
    x = (tmp ^ *(k+i)) & mod_mask;
  }

  *w = y;
  w += 1;
  *w = x;
}

void decrypt_simon_128_128(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
  uint64_t mod_mask = ULLONG_MAX;
  uint64_t x = *(uint64_t *)ciphertext;
  uint64_t y = *(((uint64_t *)ciphertext) + 1);
  uint64_t *k = (uint64_t *)key_schedule;
  uint64_t * w = (uint64_t *)plaintext;
  uint64_t tmp;

  for(int i = (rounds - 1); i >= 0; i--) {
    tmp = shift_left(x, 1) & mod_mask;
    tmp = (tmp & shift_left(x, 8)) & mod_mask;
    tmp = (tmp ^ y) & mod_mask;
    tmp = (tmp ^ shift_left(x, 2)) & mod_mask;
    y = x; // Feistell Cross
    x = (tmp ^ *(k+i)) & mod_mask;
  }

  *w = x;
  w += 1;
  *w = y;
}

int main(void)
{
  printf("Test Simon 128/128\n");
  uint8_t key_schedule[10*rounds];
  uint8_t ciphertext[16];
  uint8_t decrypted[16];
  uint8_t encryption_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t plaintext[] = {0x20, 0x74, 0x72, 0x61, 0x76, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x73, 0x20, 0x64, 0x65, 0x73, 0x63};

  expand_simon_128_128(encryption_key, key_schedule);
  encrypt_simon_128_128(key_schedule, plaintext, ciphertext);
  decrypt_simon_128_128(key_schedule, decrypted, ciphertext);

  printf("Plaintext %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n",plaintext[0],plaintext[1],plaintext[2],plaintext[3],plaintext[4],plaintext[5],plaintext[6],plaintext[7],plaintext[8],plaintext[9],plaintext[10],plaintext[11],plaintext[12],plaintext[13],plaintext[14],plaintext[15]);
  printf("Encrypted %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n",ciphertext[0],ciphertext[1],ciphertext[2],ciphertext[3],ciphertext[4],ciphertext[5],ciphertext[6],ciphertext[7],ciphertext[8],ciphertext[9],ciphertext[10],ciphertext[11],ciphertext[12],ciphertext[13],ciphertext[14],ciphertext[15]);
  printf("Decrypted %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n",decrypted[0],decrypted[1],decrypted[2],decrypted[3],decrypted[4],decrypted[5],decrypted[6],decrypted[7],decrypted[8],decrypted[9],decrypted[10],decrypted[11],decrypted[12],decrypted[13],decrypted[14],decrypted[15]);
  return 0;
}

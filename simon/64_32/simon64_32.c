/**
* simon64_32.c - Simon implementation
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

const uint8_t key_size = 4; // key_size % word_size
const uint8_t word_size = 16; // block_size % 2
const uint8_t bytes = 2; // word_size % 8
const uint8_t rounds = 32;
const uint64_t z_sequence = 0b0001100111000011010100100010111110110011100001101010010001011111;

#define ULLONG_MAX 18446744073709551615ULL

#define shift_left(x, r) ((x << r) | (x >> (word_size - r)))
#define shift_right(x, r) (x >> r) | ((x & ((1 << r) - 1)) << (word_size - r))

void expand_simon_64_32(uint8_t *key, uint8_t *key_schedule)
{
    uint8_t i;
    uint64_t keys[4] = {};

    for (i = 0; i < key_size; i++)
    {
        memcpy(&keys[i], key + (bytes * i), bytes);
    }

    memcpy(key_schedule, &keys[0], bytes);

    uint64_t mod_mask = ULLONG_MAX >> (64 - word_size);
    uint64_t c = 0xfffffffffffffffc;
    uint64_t x,y;
    for (i = 0; i < rounds; i++) {
        x = shift_right(keys[key_size - 1], 3);
        x = x ^ keys[1]; // ONLY if key_size = 4
        y = shift_right(x,1);
        x = x ^ keys[0];
        x = x ^ y;
        y = c ^ ((z_sequence >> (i % 62)) & 1);
        x = x ^ y;

        for (uint8_t i = 0; i < (key_size - 1); i++) {
          keys[i] = keys[i+1];
        }


        keys[key_size -1] = x & mod_mask;
        memcpy(key_schedule + (bytes * (i+1)), &keys[0], bytes);
        printf("X: %02x, Y: %02x, K0: %02x, K1: %02x, K2: %02x, K3: %02x \n",x,y,keys[0],keys[1],keys[2],keys[3]);
    }
}

void encrypt_simon_64_32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
    uint16_t y = *(uint16_t *)plaintext;
    uint16_t x = *(((uint16_t *)plaintext) + 1);
    uint16_t *k = (uint16_t *)key_schedule;
    uint16_t *w = (uint16_t *)ciphertext;
    uint16_t tmp;

    for(int i = 0; i < rounds; i++) {
      tmp = shift_left(x, 1);
      tmp = tmp & shift_left(x, 8);
      tmp = tmp ^ y;
      tmp = tmp ^ shift_left(x, 2);
      y = x; // Feistell Cross
      x = tmp ^ *(k+i);
      printf("X: %02x, Y: %02x \n",x,y);
    }

    *w = y;
    w += 1;
    *w = x;
    return;
}

void decrypt_simon_64_32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
    uint16_t x = *(uint16_t *)ciphertext;
    uint16_t y = *(((uint16_t *)ciphertext) + 1);
    uint16_t *k = (uint16_t *)key_schedule;
    uint16_t * w = (uint16_t *)plaintext;
    uint16_t tmp;

    for(int i = (rounds - 1); i >= 0; i--) {
        tmp = shift_left(x, 1);
        tmp = tmp & shift_left(x, 8);
        tmp = tmp ^ y;
        tmp = tmp ^ shift_left(x, 2);

        y = x; // Feistell Cross
        x = tmp ^ *(k+i);
    }

    *w = x;
    w += 1;
    *w = y;
    return;
}

int main(void)
{
    printf("Test Simon 64/32\n");
    uint8_t key_schedule[3*rounds];
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    uint8_t encryption_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
    uint8_t plaintext[] = {0x77, 0x68, 0x65, 0x65};

    expand_simon_64_32(encryption_key, key_schedule);
    encrypt_simon_64_32(key_schedule, plaintext, ciphertext);
    decrypt_simon_64_32(key_schedule, decrypted, ciphertext);

    printf("Plaintext %02x, %02x, %02x, %02x \n",plaintext[0],plaintext[1],plaintext[2],plaintext[3]);
    printf("Encrypted %02x, %02x, %02x, %02x \n",ciphertext[0],ciphertext[1],ciphertext[2],ciphertext[3]);
    printf("Decrypted %02x, %02x, %02x, %02x \n",decrypted[0],decrypted[1],decrypted[2],decrypted[3]);
    return 0;
}

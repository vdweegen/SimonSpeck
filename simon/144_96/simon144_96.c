/**
* simon144_96.c - Simon implementation
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
#include "simon144_96.h"

const uint8_t key_size = 3; // key_size % word_size
const uint8_t word_size = 48; // block_size % 2
const uint8_t bytes = 6; // word_size % 8
const uint8_t rounds = 54;
const uint64_t z_sequence = 0b0011110000101100111001010001001000000111101001100011010111011011;
const uint64_t mod_mask = 0x00FFFFFFFFFFFF;

#define shift_left(x, r) ((x << r) | (x >> (word_size - r)))
#define shift_right(x, r) (x >> r) | ((x & ((1 << r) - 1)) << (word_size - r))

void expand_simon_144_96(uint8_t *key, uint8_t *key_schedule)
{
    uint8_t i;
    uint64_t keys[4] = {};

    for (i = 0; i < key_size; i++)
    {
        memcpy(&keys[i], key + (bytes * i), bytes);
    }

    memcpy(key_schedule, &keys[0], bytes);

    uint64_t c = 0xfffffffffffffffc;
    uint64_t x,y;
    for (i = 0; i < rounds - 1; i++) {
        x = shift_right(keys[key_size - 1], 3) & mod_mask;
        y = shift_right(x,1) & mod_mask;
        x = (x ^ keys[0]) & mod_mask;
        x = (x ^ y) & mod_mask;
        y = (c ^ ((z_sequence >> (i % 62)) & 1)) & mod_mask;
        x = (x ^ y) & mod_mask;

        for (uint8_t i = 0; i < (key_size - 1); i++) {
          keys[i] = keys[i+1];
        }

        keys[key_size -1] = x & mod_mask;
        memcpy(key_schedule + (bytes * (i+1)), &keys[0], bytes);
    }
}

void encrypt_simon_144_96(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
    uint64_t y,x;
    memcpy(&y, plaintext, bytes);
    memcpy(&x, plaintext + bytes, bytes);
    uint64_t round_key, tmp;

    x = x & mod_mask;
    y = y & mod_mask;

    for(uint8_t i = 0; i < rounds; i++) {
        memcpy(&round_key, key_schedule + (bytes * i), bytes);
        round_key = round_key & mod_mask;
        tmp = (shift_left(x, 1)) & mod_mask;
        tmp = (tmp & shift_left(x, 8)) & mod_mask;
        tmp = (tmp ^ y) & mod_mask;
        tmp = (tmp ^ shift_left(x, 2)) & mod_mask;
        y = x & mod_mask; // Feistell Cross
        x = (tmp ^ round_key) & mod_mask;
    }

    bytes6_t *k = (bytes6_t *)ciphertext;
    *k = *(bytes6_t *) & y;
    k += 1;
    *k = *(bytes6_t *) & x;
}

void decrypt_simon_144_96(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
    uint64_t y,x;
    memcpy(&x, ciphertext, bytes);
    memcpy(&y, ciphertext + bytes, bytes);
    uint64_t round_key, tmp;

    x = x & mod_mask;
    y = y & mod_mask;

    for(uint8_t i = 0; i < rounds; i++) {
        memcpy(&round_key, key_schedule + (bytes * (rounds - 1 - i)), bytes);
        round_key = round_key & mod_mask;
        tmp = shift_left(x, 1);
        tmp = (tmp & shift_left(x, 8)) & mod_mask;
        tmp = (tmp ^ y) & mod_mask;
        tmp = (tmp ^ shift_left(x, 2)) & mod_mask;
        y = x & mod_mask; // Feistell Cross
        x = (tmp ^ round_key) & mod_mask;
    }

    bytes6_t *k = (bytes6_t *)plaintext;
    *k = *(bytes6_t *) & x;
    k += 1;
    *k = *(bytes6_t *) & y;
}

int main(void)
{
    printf("Test Simon 144/96\n");
    uint8_t key_schedule[6*rounds];
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    uint8_t encryption_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    uint8_t plaintext[] = {0x6f, 0x66, 0x20, 0x64, 0x75, 0x73, 0x74, 0x20, 0x74, 0x68, 0x61, 0x74};

    expand_simon_144_96(encryption_key, key_schedule);
    encrypt_simon_144_96(key_schedule, plaintext, ciphertext);
    decrypt_simon_144_96(key_schedule, decrypted, ciphertext);

    printf("Plaintext %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n",plaintext[0],plaintext[1],plaintext[2],plaintext[3],plaintext[4],plaintext[5],plaintext[6],plaintext[7],plaintext[8],plaintext[9],plaintext[10],plaintext[11]);
    printf("Encrypted %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n",ciphertext[0],ciphertext[1],ciphertext[2],ciphertext[3],ciphertext[4],ciphertext[5],ciphertext[6],ciphertext[7],ciphertext[8],ciphertext[9],ciphertext[10],ciphertext[11]);
    printf("Decrypted %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n",decrypted[0],decrypted[1],decrypted[2],decrypted[3],decrypted[4],decrypted[5],decrypted[6],decrypted[7],decrypted[8],decrypted[9],decrypted[10],decrypted[11]);
    return 0;
}

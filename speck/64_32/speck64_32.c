/**
* speck64_32.c - Speck implementation
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

// #include "speck.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const uint8_t rotation_alpha = 7;
const uint8_t rotation_beta = 2;
const uint8_t key_size = 4; // 64 / 16 = 4
const uint8_t word_size = 16;
const uint8_t bytes = 2;
const uint8_t rounds = 22;

#define rotate_right(x, r) ((x >> r) | (x << (word_size - r)))
#define rotate_left(x, r) ((x << r) | (x >> (word_size - r)))
#define ULLONG_MAX 18446744073709551615ULL

void expand_speck_64_32(uint8_t *key, uint8_t *key_schedule)
{
    uint8_t i;
    uint64_t keys[4] = {};

    for (i = 0; i < key_size; i++)
    {
        memcpy(&keys[i], key + (bytes * i), bytes);
    }

    memcpy(key_schedule, &keys[0], bytes);

    uint64_t mod_mask = ULLONG_MAX >> (64 - word_size);

    uint64_t x,y;

    for (i = 0; i < rounds - 1; i++) {
        x = rotate_right(keys[1], rotation_alpha) & mod_mask;
        x = (x + keys[0]) & mod_mask;
        x = x ^ i;
        y = rotate_left(keys[0], rotation_beta) & mod_mask;
        y = y ^ x;
        keys[0] = y;

        keys[key_size - 1] = x;

        memcpy(key_schedule + (bytes * (i+1)), &keys[0], bytes);
    }
}

void encrypt_speck_64_32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
    uint16_t y = *(uint16_t *)plaintext;
    uint16_t x = *(((uint16_t *)plaintext) + 1);
    uint16_t *k = (uint16_t *)key_schedule;
    uint16_t * w = (uint16_t *)ciphertext;
    // printf("[X] %04x [Y] %04x\n", x, y);
    for(uint8_t i = 0; i < rounds; i++) {
        x = rotate_right(x, rotation_alpha);
        // printf("[ROR X] %04x ",x);
        x = x + y;
        // printf("[ADD X] %04x ",x);
        x = x ^ *(k + i);
        // printf("[XOR X] %04x ",x);
        y = rotate_left(y, rotation_beta);
        // printf("[ROL Y] %04x ",y);
        y = y ^ x;
        // printf("[XOR Y] %04x \n",y);
    }
    printf("\n");

    *w = y;
    w += 1;
    *w = x;
    return;
}

void decrypt_speck_64_32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext)
{
    uint16_t y = *(uint16_t *)ciphertext;
    uint16_t x = *(((uint16_t *)ciphertext) + 1);
    uint16_t *k = (uint16_t *)key_schedule;
    uint16_t *w = (uint16_t *)plaintext;
    // printf("[X] %04x [Y] %04x\n", x, y);
    for(uint8_t i = 0; i < rounds; i++) {
        y = y ^ x;
        // printf("[XOR Y] %04x ",y);
        y = rotate_right(y, rotation_beta);
        // printf("[ROR Y] %04x ",y);
        x = x ^ *(k + rounds - 1 - i);
        // printf("[XOR X] %04x ",x);
        x = x - y;
        // printf("[SUB X] %04x ",x);
        x = rotate_left(x, rotation_alpha);
        // printf("[ROL X] %04x \n",x);
    }
    // printf("\n");

    *w = y;
    w += 1;
    *w = x;
    return;
}

// int main(void)
// {
//     printf("Test Speck 64/32\n");
//     uint8_t key_schedule[2*rounds];
//     uint8_t ciphertext[16];
//     uint8_t decrypted[16];
//     uint8_t encryption_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
//     uint8_t plaintext[] = {0x4c, 0x69, 0x74, 0x65};
//
//     // printf("Test Speck 64/32 Expanding\n");
//     expand_speck_64_32(encryption_key, key_schedule);
//     // printf("Test Speck 64/32 Encrypting\n");
//     encrypt_speck_64_32(key_schedule, plaintext, ciphertext);
//     // printf("Test Speck 64/32 Decryption\n");
//     decrypt_speck_64_32(key_schedule, decrypted, ciphertext);
//
//     printf("Plaintext %02x, %02x, %02x, %02x \n",plaintext[0],plaintext[1],plaintext[2],plaintext[3]);
//     printf("Encrypted %02x, %02x, %02x, %02x \n",ciphertext[0],ciphertext[1],ciphertext[2],ciphertext[3]);
//     printf("Decrypted %02x, %02x, %02x, %02x \n",decrypted[0],decrypted[1],decrypted[2],decrypted[3]);
//     return 0;
// }

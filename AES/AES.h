// EECS 4980:805 Inside Cryptography
// AES Project
// David Carek

// This file is the interface for the AES.cpp file.

#pragma once

// generates the 11x4x4 array of the needed keys for AES
void keyExpansion(unsigned char (*keys)[4][4], char * key);

// runs the encryption process on the block of 16 characters using the keys passed in
void encrypt(char text[16], unsigned char(*keys)[4][4]);

// this function is just like encrypt but it uses the inverse functions
void decrypt(char text[16], unsigned char(*keys)[4][4]);

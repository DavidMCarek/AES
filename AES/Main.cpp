// EECS 4980:805 Inside Cryptography
// AES Project
// David Carek

// This file is the main control for running AES. It reads and validates input parameters, reads from the input file, 
// calls the encrypt or decrypt function on blocks of input, and writes to the output file.

#include <iostream>
#include <fstream>
#include <string.h>
#include <string>
#include <time.h>
#include "AES.h"

void garbageGenerator(char * garbage, int size);
void blockXOR(char * b1, char * b2);

int main(int argc, char *argv[]) {

	// make sure we have input in the form 
	// AES <-action> <key> <mode> <infile> <outfile>

	// this can be accomplished by checking the number of arguments
	if (argc != 6) {
		std::cout << "Invalid arguments. AES <-action> <key> <mode> <infile> <outfile>" << std::endl;
		return 1;
	}

	// next we make sure that the action selected is valid
	bool encrypting;
	if (_stricmp(argv[1], "-d") == 0)
		encrypting = false;
	else if (_stricmp(argv[1], "-e") == 0)
		encrypting = true;
	else {
		std::cout << "Invalid action selected. Use -e or -d for encrypting/decrypting." << std::endl;
		return 1;
	}

	char key[17];

	// then we check to see if the key is 32 hex characters or 16 characters
	int keyLength = strlen(argv[2]);

	if (keyLength == 32 &&
		isxdigit(argv[2][0]) &&
		isxdigit(argv[2][1]) &&
		isxdigit(argv[2][2]) &&
		isxdigit(argv[2][3]) &&
		isxdigit(argv[2][4]) &&
		isxdigit(argv[2][5]) &&
		isxdigit(argv[2][6]) &&
		isxdigit(argv[2][7]) &&
		isxdigit(argv[2][8]) &&
		isxdigit(argv[2][9]) &&
		isxdigit(argv[2][10]) &&
		isxdigit(argv[2][11]) &&
		isxdigit(argv[2][12]) &&
		isxdigit(argv[2][13]) &&
		isxdigit(argv[2][14]) &&
		isxdigit(argv[2][15]) &&
		isxdigit(argv[2][16]) &&
		isxdigit(argv[2][17]) &&
		isxdigit(argv[2][18]) &&
		isxdigit(argv[2][19]) &&
		isxdigit(argv[2][20]) &&
		isxdigit(argv[2][21]) &&
		isxdigit(argv[2][22]) &&
		isxdigit(argv[2][23]) &&
		isxdigit(argv[2][24]) &&
		isxdigit(argv[2][25]) &&
		isxdigit(argv[2][26]) &&
		isxdigit(argv[2][27]) &&
		isxdigit(argv[2][28]) &&
		isxdigit(argv[2][29]) &&
		isxdigit(argv[2][30]) &&
		isxdigit(argv[2][31])) {

		// then we need to turn pairs of hex digits into chars. the easiest way i came 
		// up with doing this is breaking the key into 2 64 bit halves and converting 
		// them to unsigned long longs with strtoull. this makes it so that we don't have
		// to do the conversion of 2 hex digits to 1 character.
		char keyHalf1[17];
		char keyHalf2[17];
		// copy the first and second halves of the key
		strncpy_s(keyHalf1, &argv[2][0], sizeof(char) * 16);
		strncpy_s(keyHalf2, &argv[2][16], sizeof(char) * 16);
		// these 2 lines were a just in case the null character is not copied with the 
		// strncpy_s function.
		keyHalf1[16] = '\0';
		keyHalf2[16] = '\0';

		char * endPtr;
		// convert the halves to ull
		unsigned long long half1 = strtoull(keyHalf1, &endPtr, 16);
		unsigned long long half2 = strtoull(keyHalf2, &endPtr, 16);
		
		// shift and cast to get each char needed from the halves
		key[0] = (char)(half1 >> 56);
		key[1] = (char)(half1 >> 48);
		key[2] = (char)(half1 >> 40);
		key[3] = (char)(half1 >> 32);
		key[4] = (char)(half1 >> 24);
		key[5] = (char)(half1 >> 16);
		key[6] = (char)(half1 >> 8);
		key[7] = (char)(half1);
		key[8] = (char)(half2 >> 56);
		key[9] = (char)(half2 >> 48);
		key[10] = (char)(half2 >> 40);
		key[11] = (char)(half2 >> 32);
		key[12] = (char)(half2 >> 24);
		key[13] = (char)(half2 >> 16);
		key[14] = (char)(half2 >> 8);
		key[15] = (char)(half2);
	}
	else if (keyLength == 18 &&
		argv[2][0] == '\'' &&
		argv[2][17] == '\'') {
		
		strncpy_s(key, &argv[2][1], sizeof(char) * 16);
	}
	else if (keyLength == 16) {
		// since windows does not require the single ticks around the parameter i added this in just in case
		strncpy_s(key, argv[2], sizeof(char) * 16);
	}
	else {
		std::cout << "Invalid key. Must be 32 digit hex or 16 characters." << std::endl;
		return 1;
	}

	// now we need to check that the mode is ecb or cbc
	bool isCBC;
	if (_stricmp(argv[3], "cbc") == 0) {
		isCBC = true;
	}
	else if (_stricmp(argv[3], "ecb") == 0)
		isCBC = false;
	else {
		std::cout << "Invalid mode selected. Use cbc or ecb." << std::endl;
		return 1;
	}

	std::ifstream inputStream;
	inputStream.open(argv[4], std::ios::binary);

	// if we couldn't open the file, let the user know and return
	if (inputStream.fail()) {
		std::cout << "Could not open input file" << std::endl;
		return 1;
	}

	// since the file is valid we find its length
	inputStream.seekg(0, inputStream.end);
	unsigned int length = inputStream.tellg();
	inputStream.seekg(0, inputStream.beg);

	// then we make sure we can open the output file
	std::ofstream outputStream;
	outputStream.open(argv[5], std::ios::binary);
	if (outputStream.fail()) {
		std::cout << "Could not open output file" << std::endl;
		return 1;
	}

	// once we've reached this point we are ready to generate the keys for encryption/decryption
	unsigned char keys[11][4][4];
	keyExpansion(keys, key);

	// we will need a buffer to read in 16 bytes of the file at a time.
	char buffer[16];
	char previousBuffer[16];
	
	if (encrypting) {
		char iv[16];

		// if we are in CBC mode we need to setup the iv, encrypt it, and write it to the output file
		if (isCBC) {
			garbageGenerator(iv, 16);
			memcpy(buffer, iv, sizeof(iv));
			encrypt(buffer, keys);
			outputStream.write(buffer, 16);
		}

		// now we need to encrypt the block that contains the file length. the file length will be 32
		// bits of the block, the last 1/4 of it.
		garbageGenerator(buffer, 16);
		buffer[15] = length;
		buffer[14] = length >> 8;
		buffer[13] = length >> 16;
		buffer[12] = length >> 24;
		
		// if we are in cbc we need to XOR our unencrypted block that contains the file length with the
		// unencrypted iv
		if (isCBC) 
			blockXOR(buffer, iv);
		
		// then we encrypt the block
		encrypt(buffer, keys);

		// we need to keep track of the previous encrypted buffer so that the next buffer can get XORed with it
		if (isCBC)
			memcpy(previousBuffer, buffer, sizeof(buffer));

		// then we write the encrypted buffer to the output file
		outputStream.write(buffer, 16);

		// the remaining code will encrypt the plaintext of the original file
		while (length > 15) {
			// read in a block
			inputStream.read(buffer, 16);
			length -= 16;
			// if cbc mode was selected XOR the previously encrypted block with the current one
			if (isCBC)
				blockXOR(buffer, previousBuffer);

			// then we encrypt the block
			encrypt(buffer, keys);

			// if cbc is selected we need to store the encrypted block for the next block to encrypt
			if (isCBC)
				memcpy(previousBuffer, buffer, 16);

			// write the encrypted block to the output file
			outputStream.write(buffer, 16);
		}
		// if we have any characters left over in the file they will need to be padded 
		if (length > 0) {
			// read in the remaining characters
			inputStream.read(buffer, length);
			// generate garbage for the extra characters in the string
			garbageGenerator(buffer, 16 - length);
			// if we are in cbc we need to XOR the previous encrypted block with the current one
			if (isCBC)
				blockXOR(buffer, previousBuffer);

			encrypt(buffer, keys);

			// write the encrypted block to the output file
			outputStream.write(buffer, 16);
		}
	}
	else {
		
		char tempBuffer[16];

		// for cbc we read in the encrypted iv, decrypt it, and copy it into previous buffer
		if (isCBC) {
			inputStream.read(buffer, 16);
			decrypt(buffer, keys);
			memcpy(previousBuffer, buffer, sizeof(buffer));
		}

		// read the encrypted block that contains the file length 
		inputStream.read(buffer, 16);
		// if we're in cbc mode we need to hold this value for XOR with the next block
		if (isCBC)
			memcpy(tempBuffer, buffer, sizeof(buffer));

		decrypt(buffer, keys);

		// if we are in cbc we need to XOR this block with the iv
		if (isCBC) {
			blockXOR(buffer, previousBuffer);
			memcpy(previousBuffer, tempBuffer, sizeof(buffer));
		}

		// the MSByte of the length is in buffer[12] so we read it into the length.
		// then shift the length to make room for the next byte. repeat this for the
		// remaining 3 bytes.
		length = buffer[12];
		length <<= 8;
		length |= buffer[13];
		length <<= 8;
		length |= buffer[14];
		length <<= 8;
		length |= buffer[15];

		// read in the encrypted text until there is only one block remaining
		while (length > 16) {
			inputStream.read(buffer, 16);
			length -= 16;

			// if we are in cbc mode we need to save the encrypted block for the next
			// XOR with the previous block
			if (isCBC)
				memcpy(tempBuffer, buffer, 16);

			decrypt(buffer, keys);
			
			// perform the XOR with the previous block and then move in the new previous 
			// block from the temp block
			if (isCBC) {
				blockXOR(buffer, previousBuffer);
				memcpy(previousBuffer, tempBuffer, sizeof(tempBuffer));
			}
				
			// write the decrypted block to the output file
			outputStream.write(buffer, 16);
		}
		// now we decrypt the last block
		if (length > 0) {
			inputStream.read(buffer, 16);
			decrypt(buffer, keys);

			if (isCBC)
				blockXOR(buffer, previousBuffer);

			// we only need to write up to the length remaining since any remaining characters 
			// after that are just garbage used for padding
			outputStream.write(buffer, length);
		}

	}

	outputStream.close();
	inputStream.close();
	
	return 0;
}

// the garbage generator takes in a string and a size of how much garbage is needed.
void garbageGenerator(char * garbage, int size) {
	// seed the random number generator with the current time
	srand(time(0));

	// while there is garbage needed to be filled, generate a random byte and place
	// it at the 16 - size location
	while (size > 0) {
		garbage[16 - size] = rand() % 256;
		size--;
	}
}

// this is used for the XOR required for CBC mode. it takes in 2 blocks and XORs 
// each of the corresponding bytes together and stores the result in the first block
void blockXOR(char * b1, char * b2) {
	b1[0] ^= b2[0];
	b1[1] ^= b2[1];
	b1[2] ^= b2[2];
	b1[3] ^= b2[3];
	b1[4] ^= b2[4];
	b1[5] ^= b2[5];
	b1[6] ^= b2[6];
	b1[7] ^= b2[7];
	b1[8] ^= b2[8];
	b1[9] ^= b2[9];
	b1[10] ^= b2[10];
	b1[11] ^= b2[11];
	b1[12] ^= b2[12];
	b1[13] ^= b2[13];
	b1[14] ^= b2[14];
	b1[15] ^= b2[15];
}
/**
 * aes256m.cxx
 *
 * AES-256-M
 * by snovvcrash
 * 10.2017
 */

#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstring>    // std::memset
#include <algorithm>  // std::transform

#ifdef SIMULATE
  #include <iomanip>  // std::setfill, std::setw
  #include <iterator> // std::ostream_iterator
#endif

#include "rijndael.h"
#include "sha256.h"

//////////////////////////////////////////////////////////////////////
////////////////// Nb, Nk, Nr, Sbox, InvSbox, Rcon ///////////////////
//////////////////////////////////////////////////////////////////////

/////// Advanced Encryption Standard ///////
// Nb:                 4     4     4   word
// Nk:                 4     6     8   word
// Nr:                10    12    14   round
// BLOCK_SIZE:        16    16    16   byte
// KEY_SCHED_COLS:    44    52    60   word
// KEY_SCHED_SIZE:   176   208   240   byte
// KEY_HASH_SIZE:    128   192   256   bit

// Number of rows in state is always = 4
// "Column" = 32-bit word

const size_t Nb =  4; // number of columns in state
const size_t Nk =  8; // number of 32-bit words in key
const size_t Nr = 14; // number of rounds

const size_t BLOCK_SIZE = 4 * Nb;            // number of bytes in block
const size_t KEY_SCHED_COLS = Nb * (Nr + 1); // number of columns in key_shedule
const size_t KEY_HASH_SIZE = 4 * Nk;         // number of bytes in key (max possible)

/* uint8_t ROTL8(uint8_t x, size_t shift) {return ((x) << (shift)) | ((x) >> (8 - (shift)));}
void initialize_aes_sbox(uint8_t sbox[256]) {
	uint8_t p = 1, q = 1;

	// Loop invariant: p * q == 1 in the Galois field
	do {
		// Multiply p by x+1
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
		// Divide q by x+1
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;
		// Compute the affine transformation
		sbox[p] = 0x63 ^ q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
	} while (p != 1);

	sbox[0] = 0x63;
} */

static constexpr uint8_t sboxm[256] = {
	0x2b, 0xc4, 0x4d, 0xa2, 0x76, 0x99, 0x10, 0xff, 0x56, 0xb9, 0x30, 0xdf, 0x0b, 0xe4, 0x6d, 0x82,
	0xdb, 0x34, 0xbd, 0x52, 0x86, 0x69, 0xe0, 0x0f, 0xa6, 0x49, 0xc0, 0x2f, 0xfb, 0x14, 0x9d, 0x72,
	0x95, 0x7a, 0xf3, 0x1c, 0xc8, 0x27, 0xae, 0x41, 0xe8, 0x07, 0x8e, 0x61, 0xb5, 0x5a, 0xd3, 0x3c,
	0x65, 0x8a, 0x03, 0xec, 0x38, 0xd7, 0x5e, 0xb1, 0x18, 0xf7, 0x7e, 0x91, 0x45, 0xaa, 0x23, 0xcc,
	0xcb, 0x24, 0xad, 0x42, 0x96, 0x79, 0xf0, 0x1f, 0xb6, 0x59, 0xd0, 0x3f, 0xeb, 0x04, 0x8d, 0x62,
	0x3b, 0xd4, 0x5d, 0xb2, 0x66, 0x89, 0x00, 0xef, 0x46, 0xa9, 0x20, 0xcf, 0x1b, 0xf4, 0x7d, 0x92,
	0x75, 0x9a, 0x13, 0xfc, 0x28, 0xc7, 0x4e, 0xa1, 0x08, 0xe7, 0x6e, 0x81, 0x55, 0xba, 0x33, 0xdc,
	0x85, 0x6a, 0xe3, 0x0c, 0xd8, 0x37, 0xbe, 0x51, 0xf8, 0x17, 0x9e, 0x71, 0xa5, 0x4a, 0xc3, 0x2c,
	0x6f, 0x80, 0x09, 0xe6, 0x32, 0xdd, 0x54, 0xbb, 0x12, 0xfd, 0x74, 0x9b, 0x4f, 0xa0, 0x29, 0xc6,
	0x9f, 0x70, 0xf9, 0x16, 0xc2, 0x2d, 0xa4, 0x4b, 0xe2, 0x0d, 0x84, 0x6b, 0xbf, 0x50, 0xd9, 0x36,
	0xd1, 0x3e, 0xb7, 0x58, 0x8c, 0x63, 0xea, 0x05, 0xac, 0x43, 0xca, 0x25, 0xf1, 0x1e, 0x97, 0x78,
	0x21, 0xce, 0x47, 0xa8, 0x7c, 0x93, 0x1a, 0xf5, 0x5c, 0xb3, 0x3a, 0xd5, 0x01, 0xee, 0x67, 0x88,
	0x8f, 0x60, 0xe9, 0x06, 0xd2, 0x3d, 0xb4, 0x5b, 0xf2, 0x1d, 0x94, 0x7b, 0xaf, 0x40, 0xc9, 0x26,
	0x7f, 0x90, 0x19, 0xf6, 0x22, 0xcd, 0x44, 0xab, 0x02, 0xed, 0x64, 0x8b, 0x5f, 0xb0, 0x39, 0xd6,
	0x31, 0xde, 0x57, 0xb8, 0x6c, 0x83, 0x0a, 0xe5, 0x4c, 0xa3, 0x2a, 0xc5, 0x11, 0xfe, 0x77, 0x98,
	0xc1, 0x2e, 0xa7, 0x48, 0x9c, 0x73, 0xfa, 0x15, 0xbc, 0x53, 0xda, 0x35, 0xe1, 0x0e, 0x87, 0x68
};

/* void initialize_aes_inv_sbox(uint8_t inv_sbox[256]) {
	for (uint8_t i = 0; i < 255; ++i)
		inv_sbox[sbox[i]] = i;

	inv_sbox[sbox[255]] = 255;
} */

static constexpr uint8_t inv_sbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* uint8_t initialize_aes_rcon(uint8_t rcon[256]) {
	for (uint8_t i = 1; i < 255; ++i) {
		uint8_t c = i;
		uint8_t p = 1;

		while (c != 1) {
			uint8_t highbit = p & 0x80;
			p = (p << 1) & 0xff;
			if (highbit) p ^= 0x1b;
			--c;
		}

		rcon[i] = p;
	}

	rcon[0] = rcon[255] = 0x8d;
} */

/* static constexpr uint8_t rcon[256] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
} */

static constexpr uint8_t rcon[4][11] = {
	{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};

//////////////////////////////////////////////////////////////////////
//////// SubBytes(), ShiftRows(), MixColumns(), AddRoundKey() ////////
/////////// InvSubBytes(), InvShiftRows(), InvMixColumns() ///////////
//////////////////////////////////////////////////////////////////////

void subBytes(state_t state, bool inv=false) {
	uint8_t (*func)(uint8_t) = getSBoxValue;
	if (inv) func = getInvSBoxValue;

	for (size_t i = 0; i < 4; ++i)
		for (size_t j = 0; j < Nb; ++j)
			state[j][i] = func(state[j][i]);
}

void shiftRows(state_t state, bool inv=false) {
	uint8_t tmp_row[Nb];

	if (!inv)
		for (size_t i = 1; i < 4; ++i) {
			for (size_t j = 0; j < Nb; ++j)
				tmp_row[j] = state[i][j];
			for (size_t j = 0; j < Nb; ++j)
				state[i][j] = tmp_row[(j+i) % 4];
		}
	else
		for (size_t i = 1; i < 4; ++i) {
			for (size_t j = 0; j < Nb; ++j)
				tmp_row[j] = state[i][j];
			for (size_t j = 0; j < Nb; ++j)
				state[i][j] = tmp_row[((((j-i) % 4) + 4) % 4)];
		}
}

// inv = false: multiply every column in state by  3x^3 +   x^2 +  x +  2 mod x^4 + 1
// inv = true:  multiply every column in state by 11x^3 + 13x^2 + 9x + 14 mod x^4 + 1
void mixColumns(state_t state, bool inv=false) {
	for (size_t i = 0; i < Nb; ++i) {
		uint8_t s[4];

		if (!inv) {
			s[0] = mulBy02(state[0][i]) ^ mulBy03(state[1][i]) ^ state[2][i] ^ state[3][i];
			s[1] = state[0][i] ^ mulBy02(state[1][i]) ^ mulBy03(state[2][i]) ^ state[3][i];
			s[2] = state[0][i] ^ state[1][i] ^ mulBy02(state[2][i]) ^ mulBy03(state[3][i]);
			s[3] = mulBy03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ mulBy02(state[3][i]);
		}
		else {
			s[0] = mulBy0e(state[0][i]) ^ mulBy0b(state[1][i]) ^ mulBy0d(state[2][i]) ^ mulBy09(state[3][i]);
			s[1] = mulBy09(state[0][i]) ^ mulBy0e(state[1][i]) ^ mulBy0b(state[2][i]) ^ mulBy0d(state[3][i]);
			s[2] = mulBy0d(state[0][i]) ^ mulBy09(state[1][i]) ^ mulBy0e(state[2][i]) ^ mulBy0b(state[3][i]);
			s[3] = mulBy0b(state[0][i]) ^ mulBy0d(state[1][i]) ^ mulBy09(state[2][i]) ^ mulBy0e(state[3][i]);
		}

		for (size_t j = 0; j < 4; ++j) state[j][i] = s[j];
	}
}

void addRoundKey(state_t state, state_t key_schedule, size_t round=0) {
	for (size_t i = 0; i < Nb; ++i)
		for (size_t j = 0; j < 4; ++j)
			state[j][i] ^= key_schedule[j][Nb*round + i];
}

//////////////////////////////////////////////////////////////////////
//////////////// KeyExpansion(), RotWord(), SubWord() ////////////////
//////////////////////////////////////////////////////////////////////

state_t keyExpansion(uint8_t* key) {
	state_t key_schedule = allocMatrix(4, KEY_SCHED_COLS);

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nk; ++c)
			key_schedule[r][c] = key[r + 4*c];

	for (size_t i = Nk; i < KEY_SCHED_COLS; ++i) {
		uint8_t tmp_word[4];

		for (size_t j = 0; j < 4; ++j)
			tmp_word[j] = key_schedule[j][i-1];

		if (i % Nk == 0) {
			rotWord(tmp_word);
			subWord(tmp_word);
			tmp_word[0] = tmp_word[0] ^ rcon[0][i / Nk];
		}
		// 256-bit key case
		else if (Nk > 6 && i % Nk == 4)
			subWord(tmp_word);

		for (size_t j = 0; j < 4; ++j)
			key_schedule[j][i] = key_schedule[j][i - Nk] ^ tmp_word[j];
	}

	return key_schedule;
}

void rotWord(uint8_t* word) {
	uint8_t tmp = word[0];

	for (size_t i = 0; i < 3; ++i)
		word[i] = word[i + 1];
	word[3] = tmp;
}

void subWord(uint8_t* word) {
	for (size_t i = 0; i < 4; ++i)
		word[i] = getSBoxValue(word[i]);
}

//////////////////////////////////////////////////////////////////////
/////////////////////// Cipher(), InvCipher() ////////////////////////
//////////////////////////////////////////////////////////////////////

void cipher(uint8_t* block, state_t key_schedule) {
	state_t state = allocMatrix(4, Nb);

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nb; ++c)
			state[r][c] = block[r + 4*c];

	addRoundKey(state, key_schedule);

	for (size_t rnd = 1; rnd <= Nr; ++rnd) {
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, key_schedule, rnd);
	}

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nb; ++c)
			block[r + 4*c] = state[r][c];

	deallocMatrix(state, Nb);
}

void invCipher(uint8_t* block, state_t key_schedule) {
	state_t state = allocMatrix(4, Nb);

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nb; ++c)
			state[r][c] = block[r + 4*c];

	addRoundKey(state, key_schedule, Nr);

	for (int rnd = Nr - 1; rnd >= 0; --rnd) {
		shiftRows(state, true);
		subBytes(state, true);
		addRoundKey(state, key_schedule, rnd);
		if (rnd != 0)
			mixColumns(state, true);
	}

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nb; ++c)
			block[r + 4*c] = state[r][c];

	deallocMatrix(state, Nb);
}

//////////////////////////////////////////////////////////////////////
//////////// AES_ECB_EncryptFile(), AES_ECB_DecryptFile() ////////////
//////////// AES_CBC_EncryptFile(), AES_CBC_DecryptFile() ////////////
//////////////////////////////////////////////////////////////////////

void AES_ECB_EncryptFile(
	unsigned long long plaintext_size,
	std::ifstream* plaintext,
	std::ofstream* ciphertext,
	uint8_t* key) {

	state_t key_schedule = keyExpansion(key);
	unsigned long long plaintext_left;

	// Encrypting
	while ((plaintext_left = plaintext_size - plaintext->tellg())) {
		uint8_t block[BLOCK_SIZE];

		if (plaintext_left >= BLOCK_SIZE)
			plaintext->read(reinterpret_cast<char*>(block), BLOCK_SIZE);
		// Padding with zeroes except make the last byte equal to the number of padding bytes (described in [SCHN])
		else {
			plaintext->read(reinterpret_cast<char*>(block), plaintext_left);
			uint8_t padding_length = BLOCK_SIZE - plaintext_left;
			std::memset(block + plaintext_left, 0x00, padding_length - 1);
			block[BLOCK_SIZE - 1] = padding_length;
		}

		cipher(block, key_schedule);
		ciphertext->write(reinterpret_cast<char*>(block), BLOCK_SIZE);
	}

	deallocMatrix(key_schedule, 4);
}

void AES_ECB_DecryptFile(
	unsigned long long ciphertext_size,
	std::ifstream* ciphertext,
	std::ofstream* plaintext,
	uint8_t* key) {

	state_t key_schedule = keyExpansion(key);
	unsigned long long ciphertext_left;

	// Decrypting
	while ((ciphertext_left = ciphertext_size - ciphertext->tellg())) {
		uint8_t block[BLOCK_SIZE];
		size_t N = BLOCK_SIZE;

		ciphertext->read(reinterpret_cast<char*>(block), BLOCK_SIZE);
		invCipher(block, key_schedule);

		// Remove padding
		if (ciphertext_left == BLOCK_SIZE) {
			uint8_t padding_length = block[BLOCK_SIZE - 1];
			size_t count = 0;
			for (count = BLOCK_SIZE - padding_length; count < BLOCK_SIZE - 1; ++count)
				if (block[count]) break;
			if (count == ciphertext_left - 1)
				N = BLOCK_SIZE - padding_length;
		}

		plaintext->write(reinterpret_cast<char*>(block), N);
	}

	deallocMatrix(key_schedule, 4);
}

void AES_CBC_EncryptFile(
	uint8_t* iv,
	unsigned long long plaintext_size,
	std::ifstream* plaintext,
	std::ofstream* ciphertext,
	uint8_t* key) {

	state_t key_schedule = keyExpansion(key);

	unsigned long long plaintext_left;
	uint8_t fisrt_block[BLOCK_SIZE];
	uint8_t second_block[BLOCK_SIZE];

	// IV
	for (size_t i = 0; i < BLOCK_SIZE; ++i)
		fisrt_block[i] = iv[i];
	ciphertext->write(reinterpret_cast<char*>(fisrt_block), BLOCK_SIZE);

	// Encrypting
	while ((plaintext_left = plaintext_size - plaintext->tellg())) {
		if (plaintext_left >= BLOCK_SIZE)
			plaintext->read(reinterpret_cast<char*>(second_block), BLOCK_SIZE);
		// Padding with zeroes except make the last byte equal to the number of padding bytes (described in [SCHN])
		else {
			plaintext->read(reinterpret_cast<char*>(second_block), plaintext_left);
			uint8_t padding_length = BLOCK_SIZE - plaintext_left;
			std::memset(second_block + plaintext_left, 0x00, padding_length - 1);
			second_block[BLOCK_SIZE - 1] = padding_length;
		}

		// XORing prev crypted plaintext block with next non-crypted plaintext block

		/* for (size_t i = 0; i < BLOCK_SIZE; ++i)
			second_block[i] ^= fisrt_block[i]; */

		std::transform(
			second_block,
			second_block + BLOCK_SIZE,
			fisrt_block,
			second_block,
			[](uint8_t const& block_item, uint8_t const& iv_item) {
				return block_item ^ iv_item;
			}
		);

		cipher(second_block, key_schedule);
		ciphertext->write(reinterpret_cast<char*>(second_block), BLOCK_SIZE);

		std::copy(second_block, second_block + BLOCK_SIZE, fisrt_block);
	}

	deallocMatrix(key_schedule, 4);
}

void AES_CBC_DecryptFile(
	unsigned long long ciphertext_size,
	std::ifstream* ciphertext,
	std::ofstream* plaintext,
	uint8_t* key) {

	state_t key_schedule = keyExpansion(key);

	unsigned long long ciphertext_left;
	uint8_t fisrt_block[BLOCK_SIZE];
	uint8_t second_block[BLOCK_SIZE];
	uint8_t buf[BLOCK_SIZE];

	// IV
	ciphertext->read(reinterpret_cast<char*>(fisrt_block), BLOCK_SIZE);

	// Decrypting
	while ((ciphertext_left = ciphertext_size - ciphertext->tellg())) {
		size_t N = BLOCK_SIZE;

		ciphertext->read(reinterpret_cast<char*>(second_block), BLOCK_SIZE);
		std::copy(second_block, second_block + BLOCK_SIZE, buf);
		invCipher(second_block, key_schedule);

		// XORing prev non-decrypted ciphertext block with next decrypted ciphertext block

		/* for (size_t i = 0; i < BLOCK_SIZE; ++i)
			second_block[i] ^= fisrt_block[i]; */

		std::transform(
			second_block,
			second_block + BLOCK_SIZE,
			fisrt_block,
			second_block,
			[](uint8_t const& block_item, uint8_t const& iv_item) {
				return block_item ^ iv_item;
			}
		);

		// Remove padding
		if (ciphertext_left == BLOCK_SIZE) {
			uint8_t padding_length = second_block[BLOCK_SIZE - 1];
			size_t count = 0;
			for (count = BLOCK_SIZE - padding_length; count < BLOCK_SIZE - 1; ++count)
				if (second_block[count]) break;
			if (count == ciphertext_left - 1)
				N = BLOCK_SIZE - padding_length;
		}

		plaintext->write(reinterpret_cast<char*>(second_block), N);
		std::copy(buf, buf + BLOCK_SIZE, fisrt_block);
	}

	deallocMatrix(key_schedule, 4);
}

//////////////////////////////////////////////////////////////////////
////////////////////////////// TESTING ///////////////////////////////
//////////////////////////////////////////////////////////////////////

#ifdef SIMULATE
void cipherExampleVectorFIPS197(uint8_t* block, state_t key_schedule) {
	state_t state = allocMatrix(4, Nb);

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nb; ++c)
			state[r][c] = block[r + 4*c];

	std::cout << "round[ 0].input    ";
	printStateInRow(state);
	std::cout << "round[ 0].k_sch    ";
	printKeySchedInRow(key_schedule, 0, Nb);

	addRoundKey(state, key_schedule);

	for (size_t rnd = 1; rnd <= Nr; ++rnd) {
		std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << rnd << "].start    ";
		printStateInRow(state);

		subBytes(state);
		std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << rnd << "].s_box    ";
		printStateInRow(state);

		shiftRows(state);
		std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << rnd << "].s_row    ";
		printStateInRow(state);

		if (rnd != Nr) {
			mixColumns(state);
			std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << rnd << "].m_col    ";
			printStateInRow(state);
		}

		std::cout << "round["<< std::setfill(' ') << std::setw(2) << std::dec << rnd << "].k_sch    ";
		printKeySchedInRow(key_schedule, rnd * 4, rnd*4 + 4);

		addRoundKey(state, key_schedule, rnd);
	}

	std::cout << "round[" << std::dec << Nr << "].output   ";
	printStateInRow(state);

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nb; ++c)
			block[r + 4*c] = state[r][c];

	deallocMatrix(state, Nb);
}

void invCipherExampleVectorFIPS197(uint8_t* block, state_t key_schedule) {
	state_t state = allocMatrix(4, Nb);

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nb; ++c)
			state[r][c] = block[r + 4*c];

	std::cout << "round[ 0].iinput    ";
	printStateInRow(state);
	std::cout << "round[ 0].ik_sch    ";
	printKeySchedInRow(key_schedule, Nr * 4, Nr*4 + 4);

	addRoundKey(state, key_schedule, Nr);

	size_t count = 1;
	for (int rnd = Nr - 1; rnd >= 0; --rnd) {
		std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << count << "].istart    ";
		printStateInRow(state);

		shiftRows(state, true);
		std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << count << "].is_row    ";
		printStateInRow(state);

		subBytes(state, true);
		std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << count << "].is_box    ";
		printStateInRow(state);

		addRoundKey(state, key_schedule, rnd);

		if (rnd != 0) {
			mixColumns(state, true);
			std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << count << "].im_col    ";
			printStateInRow(state);
		}

		std::cout << "round["<< std::setfill(' ') << std::setw(2) << std::dec << count++ << "].ik_sch    ";
		printKeySchedInRow(key_schedule, rnd * 4, rnd*4 + 4);
	}

	std::cout << "round[" << std::dec << Nr << "].ioutput   ";
	printStateInRow(state);

	for (size_t r = 0; r < 4; ++r)
		for (size_t c = 0; c < Nb; ++c)
			block[r + 4*c] = state[r][c];

	deallocMatrix(state, Nb);
}

void AES_SimulateExampleVectorEncryptionFIPS197() {
	std::ostream_iterator<int> out(std::cout, "");

	uint8_t block[BLOCK_SIZE] = {
		(uint8_t) 0x00, (uint8_t) 0x11, (uint8_t) 0x22, (uint8_t) 0x33,
		(uint8_t) 0x44, (uint8_t) 0x55, (uint8_t) 0x66, (uint8_t) 0x77,
		(uint8_t) 0x88, (uint8_t) 0x99, (uint8_t) 0xaa, (uint8_t) 0xbb,
		(uint8_t) 0xcc, (uint8_t) 0xdd, (uint8_t) 0xee, (uint8_t) 0xff
	};

	uint8_t key[32] = {
		(uint8_t) 0x00, (uint8_t) 0x01, (uint8_t) 0x02, (uint8_t) 0x03,
		(uint8_t) 0x04, (uint8_t) 0x05, (uint8_t) 0x06, (uint8_t) 0x07,
		(uint8_t) 0x08, (uint8_t) 0x09, (uint8_t) 0x0a, (uint8_t) 0x0b,
		(uint8_t) 0x0c, (uint8_t) 0x0d, (uint8_t) 0x0e, (uint8_t) 0x0f,
		(uint8_t) 0x10, (uint8_t) 0x11, (uint8_t) 0x12, (uint8_t) 0x13,
		(uint8_t) 0x14, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x17,
		(uint8_t) 0x18, (uint8_t) 0x19, (uint8_t) 0x1a, (uint8_t) 0x1b,
		(uint8_t) 0x1c, (uint8_t) 0x1d, (uint8_t) 0x1e, (uint8_t) 0x1f
	};

	state_t key_schedule = keyExpansion(key);

	std::cout << "PLAINTEXT:    ";
	for (size_t i = 0; i < BLOCK_SIZE; ++i)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << block[i];
	std::cout << std::endl;

	std::cout << "KEY:          ";
	for (size_t i = 0; i < 32; ++i)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << key[i];
	std::cout << std::endl << std::endl;

	std::cout << "CIPHER (ENCRYPT):" << std::endl;
	cipherExampleVectorFIPS197(block, key_schedule);
	std::cout << std::endl;

	std::cout << "INVERSE CIPHER (DECRYPT):" << std::endl;
	invCipherExampleVectorFIPS197(block, key_schedule);

	deallocMatrix(key_schedule, 4);
}

void AES_SimulateBlockEncryption() {
	std::ostream_iterator<int> out(std::cout, " ");

	uint8_t block[BLOCK_SIZE] = {
		(uint8_t) 0x6b, (uint8_t) 0xc1, (uint8_t) 0xbe, (uint8_t) 0xe2,
		(uint8_t) 0x2e, (uint8_t) 0x40, (uint8_t) 0x9f, (uint8_t) 0x96,
		(uint8_t) 0xe9, (uint8_t) 0x3d, (uint8_t) 0x7e, (uint8_t) 0x11,
		(uint8_t) 0x73, (uint8_t) 0x93, (uint8_t) 0x17, (uint8_t) 0x2a
	};

	uint8_t key[32] = {
		'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
		'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
		'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
		'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	};

	SHA256 sha256;
	std::string hashString = sha256(key, KEY_HASH_SIZE);
	uint8_t* hash = reinterpret_cast<uint8_t*>(&hashString[0]);

	state_t key_schedule = keyExpansion(hash);

	std::cout << "Plaintext:" << std::endl;
	std::copy(block, block + BLOCK_SIZE, out);
	std::cout << std::endl << std::endl;

	cipher(block, key_schedule);

	std::cout << "Ciphertext:" << std::endl;
	std::copy(block, block + BLOCK_SIZE, out);
	std::cout << std::endl << std::endl;

	invCipher(block, key_schedule);

	std::cout << "Decrypted:" << std::endl;
	std::copy(block, block + BLOCK_SIZE, out);
	std::cout << std::endl;

	deallocMatrix(key_schedule, 4);
}
#endif // SIMULATE

//////////////////////////////////////////////////////////////////////
///////////////////////////// UTILITIES //////////////////////////////
//////////////////////////////////////////////////////////////////////

uint8_t getSBoxValue(uint8_t num) {
	return sboxm[num];
}

uint8_t getInvSBoxValue(uint8_t num) {
	return inv_sbox[num];
}

state_t allocMatrix(size_t rows, size_t cols) {
	state_t new_matrix = new uint8_t* [rows];

	for (size_t i = 0; i < rows; ++i)
		new_matrix[i] = new uint8_t[cols];

	return new_matrix;
}

void deallocMatrix(state_t old_matrix, size_t rows) {
	for (size_t i = 0; i < rows; ++i)
		delete [] old_matrix[i];

	delete [] old_matrix;
}

#ifdef SIMULATE
void printStateInRow(state_t state) {
	for (size_t i = 0; i < Nb; ++i)
		for (size_t j = 0; j < 4; ++j)
			std::cout << std::setfill('0') << std::setw(2) << std::hex << state[j][i];

	std::cout << std::endl;
}

void printKeySchedInRow(state_t key_schedule, size_t col_start, size_t col_end) {
	for (size_t i = col_start; i < col_end; ++i)
		for (size_t j = 0; j < 4; ++j)
			std::cout << std::setfill('0') << std::setw(2) << std::hex << key_schedule[j][i];

	std::cout << std::endl;
}

std::ostream& operator<<(std::ostream& out, uint8_t val) {
	return out << static_cast<int>(val);
}
#endif // SIMULATE

//////////////////////////////////////////////////////////////////////
//////////////////////////////// MATH ////////////////////////////////
///////////////////// Multiplication in GF(2^8) //////////////////////
//////////////////////////////////////////////////////////////////////

// 0x1b = 00011011 = 27 = x^8 + x^4 + x^3 + x + 1
// 0x80 = 10000000 = 128
// 0xff = 11111111 = 255

// x*a
uint8_t xTime(uint8_t a) {
	uint8_t highbit = a & 0x80;
	uint8_t shl = (a << 1); // & 0xff;
	return highbit == 0 ? shl : shl ^ 0x1b;
}

// {0x02}*a = 00000010*a = x*a
uint8_t mulBy02(uint8_t a) {
	return xTime(a);
}

// {0x03}*a = 00000011*a  = {0x02 ^ 0x01}*a = {0x02}*a ^ a = x*a ^ a
uint8_t mulBy03(uint8_t a) {
	return xTime(a) ^ a;
}

// {0x09}*a = 00001001*a = {0x08 ^ 0x01}*a = {{0x02}**3 ^ 0x01}*a = ...
uint8_t mulBy09(uint8_t a) {
	return xTime(xTime(xTime(a))) ^ a;
}

// {0x0b}*a = ... = {{0x02}**3 ^ {0x02} ^ 0x01}*a = ...
uint8_t mulBy0b(uint8_t a) {
	return xTime(xTime(xTime(a))) ^ xTime(a) ^ a;
}

// {0x0d}*a = ... = {{0x02}**3 ^ {0x02}**2 ^ 0x01}*a = ...
uint8_t mulBy0d(uint8_t a) {
	return xTime(xTime(xTime(a))) ^ xTime(xTime(a)) ^ a;
}

// {0x0e}*a = ... = {{0x02}**3 ^ {0x02}**2 ^ {0x02}}*a = ...
uint8_t mulBy0e(uint8_t a) {
	return xTime(xTime(xTime(a))) ^ xTime(xTime(a)) ^ xTime(a);
}

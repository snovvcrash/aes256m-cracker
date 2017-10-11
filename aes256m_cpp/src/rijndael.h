/**
 * rijndael.h
 *
 * AES (Rijndael)
 * by snovvcrash
 * 12.2016
 */

/* FIPS 197, Advanced Encryption Standard (AES) - fips-197.pdf
	http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf */

#pragma once
#ifndef RIJNDAEL_H
#define RIJNDAEL_H

using state_t = uint8_t**;
extern const size_t Nb;
extern const size_t Nk;
extern const size_t Nr;
extern const size_t BLOCK_SIZE;
extern const size_t KEY_SCHED_COLS;
extern const size_t KEY_HASH_SIZE;

//////////////////////////////////////////////////////////////////////
//////// SubBytes(), ShiftRows(), MixColumns(), AddRoundKey() ////////
/////////// InvSubBytes(), InvShiftRows(), InvMixColumns() ///////////
//////////////////////////////////////////////////////////////////////

void subBytes(state_t state, bool inv);
void shiftRows(state_t state, bool inv);
void mixColumns(state_t state, bool inv);
void addRoundKey(state_t state, state_t key_schedule, size_t round);

//////////////////////////////////////////////////////////////////////
//////////////// KeyExpansion(), RotWord(), SubWord() ////////////////
//////////////////////////////////////////////////////////////////////

state_t keyExpansion(uint8_t* key);
void rotWord(uint8_t* word);
void subWord(uint8_t* word);

//////////////////////////////////////////////////////////////////////
/////////////////////// Cipher(), InvCipher() ////////////////////////
//////////////////////////////////////////////////////////////////////

void cipher(uint8_t* block, state_t key_schedule);
void invCipher(uint8_t* block, state_t key_schedule);

//////////////////////////////////////////////////////////////////////
//////////// AES_ECB_EncryptFile(), AES_ECB_DecryptFile() ////////////
//////////// AES_CBC_EncryptFile(), AES_CBC_DecryptFile() ////////////
//////////////////////////////////////////////////////////////////////

void AES_ECB_EncryptFile(
	unsigned long long plaintext_size,
	std::ifstream* plaintext,
	std::ofstream* ciphertext,
	uint8_t* key
);
void AES_ECB_DecryptFile(
	unsigned long long ciphertext_size,
	std::ifstream* ciphertext,
	std::ofstream* plaintext,
	uint8_t* key
);
void AES_CBC_EncryptFile(
	uint8_t* iv,
	unsigned long long plaintext_size,
	std::ifstream* plaintext,
	std::ofstream* ciphertext,
	uint8_t* key
);
void AES_CBC_DecryptFile(
	unsigned long long ciphertext_size,
	std::ifstream* ciphertext,
	std::ofstream* plaintext,
	uint8_t* key
);

//////////////////////////////////////////////////////////////////////
////////////////////////////// TESTING ///////////////////////////////
//////////////////////////////////////////////////////////////////////

#ifdef SIMULATE
void cipherExampleVectorFIPS197(uint8_t* block, state_t key_schedule);
void invCipherExampleVectorFIPS197(uint8_t* block, state_t key_schedule);
void AES_SimulateExampleVectorEncryptionFIPS197();
void AES_SimulateBlockEncryption();
#endif

//////////////////////////////////////////////////////////////////////
///////////////////////////// UTILITIES //////////////////////////////
//////////////////////////////////////////////////////////////////////

uint8_t getSBoxValue(uint8_t num);
uint8_t getInvSBoxValue(uint8_t num);
state_t allocMatrix(size_t rows, size_t cols);
void deallocMatrix(state_t old_matrix, size_t rows);

#ifdef SIMULATE
void printStateInRow(state_t state);
void printKeySchedInRow(state_t key_schedule, size_t col_start, size_t col_end);
std::ostream& operator<<(std::ostream& out, uint8_t val);
#endif

//////////////////////////////////////////////////////////////////////
//////////////////////////////// MATH ////////////////////////////////
///////////////////// Multiplication in GF(2^8) //////////////////////
//////////////////////////////////////////////////////////////////////

uint8_t xTime(uint8_t item);
uint8_t mulBy02(uint8_t item);
uint8_t mulBy03(uint8_t item);
uint8_t mulBy09(uint8_t item);
uint8_t mulBy0b(uint8_t item);
uint8_t mulBy0d(uint8_t item);
uint8_t mulBy0e(uint8_t item);

#endif // RIJNDAEL_H

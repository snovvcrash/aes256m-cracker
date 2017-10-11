/**
 * main.cxx
 *
 * AES (Rijndael)
 * by snovvcrash
 * 05.2017
 */

#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <pthread.h>
#include <unistd.h>       // usleep
#include <linux/limits.h> // PATH_MAX, NAME_MAX
#include <sys/types.h>    // S_ISREG
#include <sys/stat.h>     // struct stat
#include <getopt.h>
#include "./src/rijndael.h"
#include "./src/sha256.h"

#define ERROR_CIPHER_MODE     ( -1)
#define ERROR_TARGET_PATH     ( -2)
#define ERROR_RESULT_PATH     ( -3)
#define ERROR_PASS_SYMBOL     ( -4)
#define ERROR_OPTION_TYPE     ( -5)
#define ERROR_OPTION_NUMBER   ( -6)
#define ERROR_IS_REGULAR_FILE ( -7)
#define ERROR_FILE_OPEN       ( -8)
#define ERROR_FILE_EXIST      ( -9)
#define ERROR_THREAD_CREATE   (-10)
#define ERROR_THREAD_JOIN     (-11)
#define ERROR_NOT_AES_CRYPTED (-12)

using std::cout;
using std::endl;
using std::cerr;

int finish = 0;

int checkPassSymbols(const char* str);
int isRegularFile(const char* path);
void* spinner(void* none);

int main(int argc, char* argv[]) {
#ifndef SIMULATE
	int inv = -1;
	int mode = 0;
	char* input = nullptr;
	char* output = nullptr;
	uint8_t* hash = nullptr;
	pthread_t pid = 0;
	int retval = 0;

	char help[] =
		"REQUIRED OPTIONS\n"
		"	-e | -d\n"
		"	    Encryption | decryption operation respectively\n"
		"\n"
		"	--mode (-m) m\n"
		"	    Cipher mode, m can be \"ECB\" (\"ecb\") or \"CBC\" (\"cbc\")\n"
		"\n"
		"	--input (-i) i\n"
		"	    Operation input, i can be either a full path to a regular file\n"
		"	    or a filename of a regular file (if the file is in current directory)\n"
		"	    with maximum length of PATH_MAX (see value in <linux/limits.h>)\n"
		"\n"
		"	--output (-o) o\n"
		"	    Operation output, o can be either a full path with a filename\n"
		"	    or a filename (file will be created in current directory)\n"
		"	    with maximum length of PATH_MAX (see value in <linux/limits.h>)\n"
		"\n"
		"	--pass (-p) p\n"
		"	    Password that is used for creating a secret key for encryption(decryption)\n"
		"	    operation, p is a string of chars in (0x20, 07f) ASCII-table codes with\n"
		"	    unlimited length\n";
		
#ifndef DEBUG
	char help_build[] = "\nBUILD: DEFAULT (-O2 OPTIMIZATION)\n";
#else
	char help_build[] = "\nBUILD: DEBUG (-O0 OPTIMIZATION)\n";
#endif

	// ------------------------------------------------------
	// ----------------- GETOPT_LONG START ------------------
	// ------------------------------------------------------

	const char* optstring = "edm:i:o:p:h";

	const struct option longopts[] = {
		{ "mode",   required_argument, NULL, 'm' },
		{ "input",  required_argument, NULL, 'i' },
		{ "output", required_argument, NULL, 'o' },
		{ "pass",   required_argument, NULL, 'p' },
		{ "help",   no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int opt_curr  =  0;
	int longindex = -1;

	while ((opt_curr = getopt_long(argc, argv, optstring, longopts, &longindex)) != -1) {
		switch (opt_curr) {
			case 'e' : {
				inv = 0;
				break;
			}
			case 'd' : {
				inv = 1;
				break;
			}
			case 'm' : {
				char* mode_str = optarg;
				if (!std::strcmp(mode_str, "ECB") || !std::strcmp(mode_str, "ecb"))
					mode = 1;
				else if (!std::strcmp(mode_str, "CBC") || !std::strcmp(mode_str, "cbc"))
					mode = 2;
				else {
					cerr << "main: Invalid cipher mode, rerun with -h for help" << endl;
					return ERROR_CIPHER_MODE;
				}
				break;
			}
			case 'i' : {
				input = optarg;
				if (std::strlen(input) > PATH_MAX) {
					cerr << "main: Invalid input path, rerun with -h for help" << endl;
					return ERROR_TARGET_PATH;
				}
				break;
			}
			case 'o' : {
				output = optarg;
				if (std::strlen(output) > PATH_MAX) {
					cerr << "main: Invalid output path, rerun with -h for help" << endl;
					return ERROR_RESULT_PATH;
				}
				break;
			}
			case 'p' : {
				if (checkPassSymbols(optarg)) {
					cerr << "main: Invalid symbol in password, rerun with -h for help" << endl;
					return ERROR_PASS_SYMBOL;
				}
				SHA256 sha256;
				std::string hashString = sha256(optarg, KEY_HASH_SIZE);
				hash = reinterpret_cast<uint8_t*>(&hashString[0]);
				break;
			}
			case 'h' : {
				cout << help << help_build;
				return 0;
			}
			case '?' : default : {
				cerr << "main: Invalid option, rerun with -h for help" << endl;
				return ERROR_OPTION_TYPE;
			}
		}
	}

	// ------------------------------------------------------
	// ------------------ GETOPT_LONG END -------------------
	// ------------------------------------------------------

	// Checking if input is a regular file
	if (!isRegularFile(input)) {
		cerr << "main: No such input or input is not a regular file, rerun with -h for help" << endl;
		return ERROR_IS_REGULAR_FILE;
	}

	// Opening infile (input) if it is a regular file
	std::ifstream infile(
		input,
		std::ios::in |
		std::ios::binary |
		std::ios::ate
	);

	if (!infile.is_open()) {
		cerr << "main: " << std::strerror(errno) << endl;
		return ERROR_FILE_OPEN;
	}

	// If infile is opened
	unsigned long long infile_size = infile.tellg();
	infile.unsetf(std::ios::skipws);
	infile.seekg(0, std::ios::beg);

	// Checking if outfile already exists
	/*if (std::ifstream(output)) {
		cout << "main: File already exists" << endl;
		return ERROR_FILE_EXIST;
	}*/

	// Opening outfile if it does not exist
	std::ofstream outfile(
		output,
		std::ios::out |
		std::ios::binary
	);

	if (!outfile.is_open()) {
		cerr << "main: " << std::strerror(errno) << endl;
		return ERROR_FILE_OPEN;
	}

	// If outfile is opened
	if (!inv) {
		if (pthread_create(&pid, NULL, spinner, NULL)) {
			cout << "main: Bad thread creation" << endl;
			return ERROR_THREAD_CREATE;
		}

		auto start = std::chrono::steady_clock::now();

		if (mode == 1)
			AES_ECB_EncryptFile(infile_size, &infile, &outfile, hash);
		else if (mode == 2) {
			uint8_t iv[BLOCK_SIZE];
			std::srand(std::time(nullptr));
			for (size_t i = 0; i < BLOCK_SIZE; ++i)
				iv[i] = rand() % 256;
			AES_CBC_EncryptFile(iv, infile_size, &infile, &outfile, hash);
		}

		auto end = std::chrono::steady_clock::now();
		long double diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

		finish = 1;
		if (pthread_join(pid, (void**)&retval)) {
			cout << "main: Bad thread join" << endl;
			return ERROR_THREAD_JOIN;
		}

		cout.precision(4);
		cout << "File size:      " << static_cast<double>(infile_size) / 1048576 << " Mbyte" << endl;
		cout << "Time taken:     " << diff / 1000 << " seconds" << endl;
		cout << "Encrypted file: " << output << endl;
		cout << std::fixed;
	}
	else {
		if (!(infile_size % BLOCK_SIZE)) {
			if (pthread_create(&pid, NULL, spinner, NULL)) {
				cout << "main: Bad thread creation" << endl;
				return ERROR_THREAD_CREATE;
			}

			auto start = std::chrono::steady_clock::now();

			if (mode == 1)
				AES_ECB_DecryptFile(infile_size, &infile, &outfile, hash);
			else if (mode == 2)
				AES_CBC_DecryptFile(infile_size, &infile, &outfile, hash);

			auto end = std::chrono::steady_clock::now();
			long double diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

			finish = 1;
			if (pthread_join(pid, (void**)&retval)) {
				cout << "main: Bad thread join" << endl;
				return ERROR_THREAD_JOIN;
			}

			cout.precision(4);
			cout << "File size:      " << static_cast<double>(infile_size) / 1048576 << " Mbyte" << endl;
			cout << "Time taken:     " << diff / 1000 << " seconds" << endl;
			cout << "Decrypted file: " << output << endl;
			cout << std::fixed;
		}
		else {
			cerr << "main: File is not AES-crypted" << endl;
			return ERROR_NOT_AES_CRYPTED;
		}
	}

	infile.close();
	outfile.close();

#else
	char help[] =
		"POSSIBLE OPTIONS (choose one of the following)\n"
		"	--simulate-exmpl-vector\n"
		"	    Simulate encryption(decryption) of the examle vector submitted in the FIPS197 (Appendix C)\n"
		"\n"
		"	--simulate-block\n"
		"	    Simulate encryption(decryption) of a test block with key hashed via SHA256\n"
		"\nBUILD: SIMULATION\n";

	if (argc == 2) {
		if (!std::strcmp(argv[1], "--simulate-exmpl-vector"))
			AES_SimulateExampleVectorEncryptionFIPS197();

		else if (!std::strcmp(argv[1], "--simulate-block"))
			AES_SimulateBlockEncryption();

		else if (!std::strcmp(argv[1], "-h"))
			cout << help;

		else {
			cerr << "main: Invalid option, rerun with -h for help" << endl;
			return ERROR_OPTION_TYPE;
		}
	}
	else {
		cerr << "main: Invalid number of options, rerun with -h for help" << endl;
		return ERROR_OPTION_NUMBER;
	}
#endif // SIMULATE

	return 0;
}

int checkPassSymbols(const char* str) {
	int length = std::strlen(str);

	for (int i = 0; i < length; ++i)
		// if (str[i] <= SPACE || str[i] >= DEL)
		if (str[i] <= 0x20 || str[i] >= 0x7f)
			return 1;

		return 0;
}

int isRegularFile(const char* path) {
	struct stat s;
	stat(path, &s);
	return S_ISREG(s.st_mode);
}

void* spinner(void* none) {
	static constexpr char spin_chars[] = "/-\\|";
	int i = 0;

	while (!finish) {
		cout << "Processing, please wait... " << spin_chars[i++ % sizeof(spin_chars)];
		cout.flush();
		usleep(100000);
		cout << "\r";
	}

	cout << "Processing, please wait... Done" << endl;
	return nullptr;
}

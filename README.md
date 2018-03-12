# aes256m-cracker
A demonstration program of cracking the training version of AES-256.

## AES-256-M
Let's define a modified version of AES-256 (call it "AES-256-M") which would differ from the original only by the contents of its S-box, namely the new S-box would be:

```
2b c4 4d a2 76 99 10 ff 56 b9 30 df 0b e4 6d 82
db 34 bd 52 86 69 e0 0f a6 49 c0 2f fb 14 9d 72
95 7a f3 1c c8 27 ae 41 e8 07 8e 61 b5 5a d3 3c
65 8a 03 ec 38 d7 5e b1 18 f7 7e 91 45 aa 23 cc
cb 24 ad 42 96 79 f0 1f b6 59 d0 3f eb 04 8d 62
3b d4 5d b2 66 89 00 ef 46 a9 20 cf 1b f4 7d 92
75 9a 13 fc 28 c7 4e a1 08 e7 6e 81 55 ba 33 dc
85 6a e3 0c d8 37 be 51 f8 17 9e 71 a5 4a c3 2c
6f 80 09 e6 32 dd 54 bb 12 fd 74 9b 4f a0 29 c6
9f 70 f9 16 c2 2d a4 4b e2 0d 84 6b bf 50 d9 36
d1 3e b7 58 8c 63 ea 05 ac 43 ca 25 f1 1e 97 78
21 ce 47 a8 7c 93 1a f5 5c b3 3a d5 01 ee 67 88
8f 60 e9 06 d2 3d b4 5b f2 1d 94 7b af 40 c9 26
7f 90 19 f6 22 cd 44 ab 02 ed 64 8b 5f b0 39 d6
31 de 57 b8 6c 83 0a e5 4c a3 2a c5 11 fe 77 98
c1 2e a7 48 9c 73 fa 15 bc 53 da 35 e1 0e 87 68
```

This repo provides an cli-utility to crack a ciphertext crypted with AES-256-M in ECB mode only with one pair of {*P, C*} available (*P* - a block of plaintext, *C* - the corresponding block of ciphertext).

## Usage
1. Encrypt some file using `aes256.cpp` (`aes256m_cpp` folder):
```
$ make
$ ./aes256m -e -m ECB -i /path/to/plaintext -o ciphertext -p v3ry_s3cr3t_p4ssw0rd
```
2. Get the string containing the first block of the plaintext (with `xxd` for example) and copy it to the clipboard:
```
$ xxd /path/to/plaintext | head -n 1 | cut -d " " -f 2-9 | tr -d " "
```
3. Crack the ciphertext using `cracker.py` (`cracker` folder):
```
$ python3 crack.py 00ff00ff00ff00ff00ff00ff00ff00ff /path/to/ciphertext
```
(where `00ff00ff00ff00ff00ff00ff00ff00ff` is the first block of plaintext).

"""
@file generate_affine_sbox.py
@author snovvcrash <snovvcrash@protonmail.com>
@date 2017-08

@brief Generating affine sbox (like the one used in AES-256-M)

@license
Copyright (C) 2017 snovvcrash

This file is part of aes256m-cracker.

aes256m-cracker is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

aes256m-cracker is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with aes256m-cracker.  If not, see <http://www.gnu.org/licenses/>.
@endlicense
"""

import numpy as np
import random
import math
import sys

from itertools import product

# ----------------------------------------------------------
# ---------------------- AFFINE SBOX -----------------------
# ----------------------------------------------------------

"""
Affine function: y(x) = M*x + v, where
                 M is 8x8 boolean matrix,
	             v is 8-bit constant vector column,
	             * is bitwise AND (&),
	             + is bitwise XOR (^).
"""

def affine_function(x, M, v):
	Mx = (np.dot(M, x) % 2).T
	y = Mx ^ v
	return y

def S(x, M, v, bin_length):
	raw_value = list(affine_function(to_bin(x, bin_length), M, v).flat)
	return int(''.join([ str(b) for b in raw_value ]), 2)

def generate_affine_sbox(length):
	bin_length = len(bin(length-1)[2:])

	np.random.seed()
	while True:
		M = np.random.randint(0, 2, size=(bin_length, bin_length))
		if np.linalg.det(M).astype(int) % 2:
			break

	v = np.random.randint(0, 2, size=(1, bin_length))

	sbox = [ S(i, M, v, bin_length) for i in range(length) ]
	if not any_duplicates(sbox) and is_sbox_degenerate(sbox):
		return (sbox, M, v)
	return (None, None, None)

# ----------------------------------------------------------
# ------------------ SIMULATE AFFINE SBOX ------------------
# ----------------------------------------------------------

def next_unique(sample, sbox):
	while True:
		front = sample.pop()
		if front not in sbox:
			return front

def xor(x, y, z):
	return x ^ y ^ z

def emulate_affine_sbox_generation():
	sample = random.sample(range(256), 256)
	sbox = [-1] * 256

	# 0..16
	for i in range(0, 16):
		if i == 0 or i == 1 or i == 2 or i == 4 or i == 8:
			sbox[i] = next_unique(sample, sbox)

		elif i == 3 or i == 5 or i == 7 or i == 9 or i == 11 or i == 13 or i == 15:
			sbox[i] = xor(sbox[i-3] ,sbox[i-2], sbox[i-1])

		elif i == 6 or i == 10 or i == 14:
			sbox[i] = xor(sbox[i-6], sbox[i-4], sbox[i-2])

		elif i == 12:
			sbox[i] = xor(sbox[i-12], sbox[i-8], sbox[i-4])

	# 16..256
	for i in range(16, 256):
		if i == 16 or i == 32 or i == 64 or i == 128:
			sbox[i] = next_unique(sample, sbox)

		elif i in range(17, 32) or i in range(33, 48) or i in range(65, 80) or i in range(129, 144):
			sbox[i] = xor(sbox[i-17], sbox[i-1], sbox[i-16])

		elif i in range(80, 96) or i in range(144, 160) or i in range(208, 224):
			sbox[i] = xor(sbox[0], sbox[16], sbox[i-16])

		elif i in range(96, 112) or i in range(160, 176) or i in range(224, 240):
			sbox[i] = xor(sbox[0], sbox[32], sbox[i-32])

		elif i in range(192, 208):
			sbox[i] = xor(sbox[0], sbox[64], sbox[i-64])

		elif i in range(48, 64) or i in range(112, 128) or i in range(176, 192) or i in range(240, 256):
			sbox[i] = xor(sbox[i-48], sbox[i-32], sbox[i-16])

	if not any_duplicates(sbox) and is_sbox_degenerate(sbox):
		return sbox
	return None

# ----------------------------------------------------------
# ----------------------- UTILITIES ------------------------
# ----------------------------------------------------------

def to_bin(number, bin_length):
	return np.array([ [int(b)] for b in bin(number)[2:].zfill(bin_length) ])

def print_sbox(name, sbox, length):
	dim = math.sqrt(length)
	print('{} = {{'.format(name), end='')

	if dim.is_integer():
		print('\n\t', end='')
		for i in range(length):
			if not (i % dim) and i:
				print('\n\t', end='')
			print('{: >5}'.format(sbox[i]), end=', ')
		print('.\n}')
	else:
		for item in sbox:
			print(item, end=', ')
		print('.}')

def any_duplicates(sbox):
	seen = set()
	for item in sbox:
		if item not in seen:
			seen.add(item)
		else:
			return True
	return False

def is_sbox_degenerate(sbox):
	length = len(sbox)

	diff_table = [[0] * length for _ in range(length)]
	for c, d in product( *([list(range(length))]*2) ):
		diff_table[c ^ d][sbox[c] ^ sbox[d]] += 1

	count_prob = 0
	for c, d in product( *([list(range(length))]*2) ):
		if diff_table[c][d] == length:
			count_prob += 1
		#print('{} : {} -> {}'.format(diff_table[c][d], c, d))

	return count_prob == length

# ----------------------------------------------------------
# -------------------------- MAIN --------------------------
# ----------------------------------------------------------

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print('usage: python3 {} <sbox_length>'.format(sys.argv[0]))
		sys.exit(1)

	try:
		length = int(sys.argv[1])
	except ValueError:
		print("Invalid input type")
		sys.exit(1)

	if length & (length-1) != 0 or length < 1:
		print("Sbox length must be a power of two and > 1")
		sys.exit(1)

	# print(emulate_affine_sbox_generation())

	while True:
		sbox, M, v = generate_affine_sbox(length)
		if sbox:
			print('M = \n{}\n'.format(repr(M)))
			print('v = \n{}\n'.format(repr(v)))
			print_sbox('Affine Sbox', sbox, length)
			break

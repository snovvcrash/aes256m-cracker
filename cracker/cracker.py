#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
@file cracker.py
@author snovvcrash <scr.im/emsnovvcrash>
@date 2017-10

@brief Cracking AES-256-M

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

import os
import sys
import numpy as np

from invL import invL

def decblock_to_binstate(decblock):
	decstate = [ decblock[r + 4*c] for r in range(4) for c in range(4) ]
	return np.array([ [int(b)] for byte in decstate for b in bin(byte)[2:].zfill(8) ])

def binstate_to_decblock(binstate):
	decstate = [ int(''.join(str(b) for b in binstate[a:b]), 2) for a, b in zip(range(0, 121, 8), range(8, 129, 8)) ]
	return [ decstate[r + 4*c] for r in range(4) for c in range(4) ]

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print('usage: python3 {} <known_plaintext_block_in_hex> </path/to/ciphertext>'.format(sys.argv[0]))
		sys.exit(1)

	allowed_set = set('0123456789abcdef')

	if len(sys.argv[1]) != 32 or not set(sys.argv[1]) <= allowed_set:
		print('Block must be contain 32 chars from {\'0123456789abcdef\'}')
		sys.exit(1)

	if not os.path.isfile(sys.argv[2]):
		print('File does not exist')
		sys.exit(1)

	# Known block of plaintext
	P0_block = [ int(sys.argv[1][i:i+2], 16) for i in range(0, len(sys.argv[1]), 2) ]
	P0 = decblock_to_binstate(P0_block)

	invL2  =   invL.dot(invL) % 2
	invL3  =  invL2.dot(invL) % 2
	invL4  =  invL3.dot(invL) % 2
	invL5  =  invL4.dot(invL) % 2
	invL6  =  invL5.dot(invL) % 2
	invL7  =  invL6.dot(invL) % 2
	invL8  =  invL7.dot(invL) % 2
	invL9  =  invL8.dot(invL) % 2
	invL10 =  invL9.dot(invL) % 2
	invL11 = invL10.dot(invL) % 2
	invL12 = invL11.dot(invL) % 2
	invL13 = invL12.dot(invL) % 2
	invL14 = invL13.dot(invL) % 2  # L^{-14}

	with open(sys.argv[2], 'rb') as ciphertext:
		# Ciphertext block corresponding to the known plaintext block
		C0_block = list(ciphertext.read(16))
		C0 = decblock_to_binstate(C0_block)

		with open('cracked', 'wb') as cracked:
			cracked.write(bytes(P0_block))

			while True:
				Ci_block = list(ciphertext.read(16))
				if not Ci_block:
					print('DONE\nRecovered file: {}'.format(os.path.realpath(cracked.name)))
					break
				Ci = decblock_to_binstate(Ci_block)

				# The core of cracking: Pi = P0 + L^{-14}*(C0 + Ci)
				Pi = (P0 ^ (invL14.dot((C0 ^ Ci)) % 2)).T.ravel()

				Pi_block = binstate_to_decblock(Pi)
				cracked.write(bytes(Pi_block))

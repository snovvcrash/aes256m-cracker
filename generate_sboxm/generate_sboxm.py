#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@file generate_sboxm.py
@author Sam Freeside <snovvcrash@protonmail[.]ch>
@date 2017-08

@brief Re-creating the algorithm of generating the Sbox-M (used in AES-256-M).

@license
Copyright (C) 2017 Sam Freeside

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

from generate_affine_sbox import S, print_sbox

original_sboxm = [0x2b, 0xc4, 0x4d, 0xa2, 0x76, 0x99, 0x10, 0xff, 0x56, 0xb9, 0x30, 0xdf, 0x0b, 0xe4, 0x6d, 0x82,
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
                  0xc1, 0x2e, 0xa7, 0x48, 0x9c, 0x73, 0xfa, 0x15, 0xbc, 0x53, 0xda, 0x35, 0xe1, 0x0e, 0x87, 0x68]


def generate_sboxm():
	M = np.array([ [0, 1, 1, 1, 0, 0, 0, 1],
                   [1, 1, 0, 1, 1, 1, 1, 1],
                   [0, 1, 1, 1, 1, 0, 1, 1],
                   [0, 0, 1, 1, 1, 1, 0, 0],
                   [0, 0, 1, 0, 1, 1, 0, 1],
                   [1, 0, 1, 0, 1, 1, 1, 1],
                   [0, 0, 1, 0, 0, 0, 1, 1],
                   [0, 0, 0, 0, 1, 1, 0, 1] ])

	v = np.array([ [0, 0, 1, 0, 1, 0, 1, 1] ])  # binary(0x2b) = binary(43)

	return [ S(i, M, v, 8) for i in range(256) ]


if __name__ == '__main__':
	sboxm = generate_sboxm()
	print_sbox('Sbox-M', sboxm, 256)

	assert sboxm == original_sboxm, 'MISMATCH!'
	print('\nMATCH!')

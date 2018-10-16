#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@file comparator.py
@author Sam Freeside <snovvcrash@protonmail[.]ch>
@date 2017-10

@brief An utility to check the correctness of AES-256-M's matrix-oriented transformations.

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

import random
import numpy as np

import aes256m.standard.transformations as standard
import aes256m.matrix.transformations as matrix

# ----------------------------------------------------------
# ----------------------- Comparator -----------------------
# ----------------------------------------------------------


class Comparator:
	def __init__(self, state=None):
		if not state:
			# If state is not explicitly specified, then generating random
			self._state = random.sample(range(256), 16)
		else:
			self._state = state
		# Converting state to binary (128-bit)
		self._bin_state = np.array([ [int(b)] for byte in self._state for b in bin(byte)[2:].zfill(8) ])

	def compare_transformation(self, transform_standard, transform_matrix):
		print('Testing transformation: ', transform_standard.__name__.upper())
		print('------------------------------------')

		state_st = transform_standard(self._state)
		bin_state_mat = transform_matrix(self._bin_state)

		# Converting bin_state_mat to decimal
		state_mat = [ int(''.join(str(b) for b in bin_state_mat[a:b]), 2) for a, b in zip(range(0, 121, 8), range(8, 129, 8)) ]

		print('Original:            ', self._state)
		print('Modified (standard): ', state_st)
		print('Modified (matrix):   ', state_mat)

		assert state_st == state_mat, 'MISMATCH!'
		print('\nMATCH!')

		print('------------------------------------')


# ----------------------------------------------------------
# -------------------------- Main --------------------------
# ----------------------------------------------------------


if __name__ == '__main__':
	cmp = Comparator()

	cmp.compare_transformation(standard.sub_bytes, matrix.sub_bytes)
	cmp.compare_transformation(standard.shift_rows, matrix.shift_rows)
	cmp.compare_transformation(standard.mix_columns, matrix.mix_columns)
	cmp.compare_transformation(standard.linear_diffusion_layer, matrix.linear_diffusion_layer)

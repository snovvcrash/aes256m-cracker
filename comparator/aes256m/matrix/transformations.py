"""
@file transformations.py
@author snovvcrash <snovvcrash@protonmail.com>
@date 2017-10

@brief AES-256-M's linear transformations, matrix implementation

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
from .lib.sblib  import SB
from .lib.srlib  import SR
from .lib.mclib  import MC
from .lib.vlib   import V
from .lib.ldllib import L

# ----------------------------------------------------------
# ------------------------ SubBytes ------------------------
# ----------------------------------------------------------

def sub_bytes(state):
	return matrix_transformation(state, SB, V)

# ----------------------------------------------------------
# ----------------------- ShiftRows ------------------------
# ----------------------------------------------------------

def shift_rows(state):
	return matrix_transformation(state, SR)

# ----------------------------------------------------------
# ----------------------- MixColumns -----------------------
# ----------------------------------------------------------

def mix_columns(state):
	return matrix_transformation(state, MC)

# ----------------------------------------------------------
# ----------------- Linear Diffusion Layer -----------------
# ----------------------------------------------------------

"""
] x = state

x |-> MC*SR*(SB*x + V) = MC*SR*SB*x + MC*SR*V
MC*V = SR*V = V => MC*SR*V = V

x |-> MC*SR*SB*x + V = L*x + V
L = MC*SR*SB
"""

def linear_diffusion_layer(state):
	return matrix_transformation(state, L, V)

# ----------------------------------------------------------
# ----------------------- UTILITIES ------------------------
# ----------------------------------------------------------

"""
] x = state
  M = matrix
  V = vector
  k = key

x |-> M*x + k + V
"""

def matrix_transformation(state, matrix, key=np.zeros(128, int), vector=np.zeros(128, int)):
	return (matrix.dot(state) % 2).T.ravel() ^ key ^ vector

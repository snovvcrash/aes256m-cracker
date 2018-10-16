#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@file V.py
@author Sam Freeside <snovvcrash@protonmail[.]ch>
@date 2017-10

@brief Offset vector used in SubBytes transformation (AES-256-M).

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

"""
V = (0, 0, 1, 0, 1, 0, 1, 1, ..., 0, 0, 1, 0, 1, 0, 1, 1)
V - 128-bit binary vector
"""

V = [0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1]


def buildV():
	return [0, 0, 1, 0, 1, 0, 1, 1] * 16  # [ binary(0x2b) ] * 16


if __name__ == '__main__':
	print(buildV())

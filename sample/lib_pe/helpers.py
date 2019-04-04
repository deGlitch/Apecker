# -*- coding: utf-8 -*-
import math
from itertools import *


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def decodeBinaryString(bytes):
    "gets bytes string and strip the zeros from it and decodes it to UTF-8"
    # decodeBinaryString('.text\x00\x00') --> .text
    return bytes.strip(b'\x00').decode('utf-8')


def alignAddress(address, alignment):
    "align memory/file address by rounding up according to a given alignment"
    # alignAddress(1600, 1000) --> 2000
    if alignment == 0:
        return address

    remainder = address % alignment
    distance_from_aligned_address = alignment - remainder

    return address + distance_from_aligned_address

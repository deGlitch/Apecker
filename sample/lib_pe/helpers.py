# -*- coding: utf-8 -*-
from itertools import *

def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)

def decodeBinaryString(bytes):
    return bytes.strip(b'\x00').decode('utf-8')
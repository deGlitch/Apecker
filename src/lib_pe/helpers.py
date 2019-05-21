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

    if address % alignment == 0:
        return address

    remainder = address % alignment
    distance_from_aligned_address = alignment - remainder

    return address + distance_from_aligned_address

def read_until_null_byte(data):
    data_read = b''
    while(True):
        next_byte = bytes([data[len(data_read)]])
        if next_byte == b'\x00':
            break
        data_read += next_byte
    return data_read

def copy_to_list(start_address, data, to_be_mapped_list):
    
    if start_address > len(to_be_mapped_list):
        raise ValueError("the start address cannot be bigger then the size of the to be mapped list")
    
    if (start_address + len(data)) > len(to_be_mapped_list):
        raise ValueError("the data must fit into the to be mapped list")
    
    for index in range(0, len(data)):
        to_be_mapped_list[start_address+index] = bytes([data[index]])

def calculate_entropy(data):
    bytes_count_list = [0] * 256
    for byte in data:
        bytes_count_list[byte] += 1
    
    entropy = 0
    for byte_count in bytes_count_list:
        avg = byte_count/len(data)
        if(avg > 0):
            entropy -= avg * math.log2(avg)
    return entropy
# -*- coding: utf-8 -*-
class StructDefinition:
    def __init__(self, size, packer_format):
        self.size = size
        self.format = packer_format

DOS_STRUCT = StructDefinition(0x40, 'HHHHHHHHHHHHHH8sHH20sI')
NT_HEADER = StructDefinition(0xf8, 'I20s224s')
FILE_HEADER = StructDefinition(0x14, "HHIIIHH")
OPTIONAL_HEADER_32 = StructDefinition(0xe0, "HBBIIIIIIIIIHHHHHHIIIIHHIIIIII128s")
DATA_DIRECTORY = StructDefinition(0x8, "II")
SECTION_HEADER = StructDefinition(0x28, "8sIIIIIIHHI")


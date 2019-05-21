# -*- coding: utf-8 -*-
class StructDefinition:
    def __init__(self, size, packer_format):
        self.size = size
        self.format = packer_format

DOS_STRUCT = StructDefinition(0x40, 'HHHHHHHHHHHHHH8sHH20sI')
NT_HEADER = StructDefinition(0xf8, 'I20s224s')
FILE_HEADER = StructDefinition(0x14, "HHIIIHH")
OPTIONAL_HEADER_32 = StructDefinition(0xe0, "HBBIIIIIIIIIHHHHHHIIIIHHIIIIII128s")
SECTION_HEADER = StructDefinition(0x28, "8sIIIIIIHHI")

# Directories
DATA_DIRECTORY = StructDefinition(0x8, "II")

# Import Descriptor
IMAGE_IMPORT_DESCRIPTOR = StructDefinition(0x14, "IIIII")
IMAGE_THUNK_DATA32 = StructDefinition(0x4, "I")
#IMAGE_IMPORT_BY_NAME = (0x3, "")






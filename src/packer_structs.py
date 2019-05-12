# -*- coding: utf-8 -*-
class StructDefinition:
    def __init__(self, size, packer_format):
        self.size = size
        self.format = packer_format
    

PACKED_FILE_DESCRIPTOR = StructDefinition(0x10, "HII") # num_of_sections, packe_data_size, unpacked_data_size
# -*- coding: utf-8 -*-
from lib_pe.core import PortableExecutable
from lib_pe.permission_creator import PermissionsCreator
from . import packer_structs
import struct 


class PackedFileInfo:
        def __init__(self, sections_num, unpacked_data_size, packed_data_size):
                self.__sections_num = sections_num
                self.__unpacked_data_size = unpacked_data_size
                self.__packed_data_size = packed_data_size
        def pack():
                return struct.pack(packer_structs.PACKED_FILE_DESCRIPTOR.format, self.__sections_num, self.__unpacked_data_size, self.__packed_data_size)

def apecker():
        print("Start")
        file_content = open(r'C:\\Users\\Parzival\Desktop\\Project\\Apecker\\downloads\\calc32.exe','rb').read()
        parsed_file = PortableExecutable(file_content)

        # combine all headers and data
        combined_headers_buffer = b''
        combined_data_buffer = b''

        for section in parsed_file.sections:
                combined_headers_buffer += section.header.pack()
                combined_data_buffer += section.data

        # compress 

        # create packed file info

        # create new section

        #parsed_file.add_section(".compressed", b'asafasaf', PermissionsCreator.create())

        number_of_sections = len(parsed_file.sections)
        packed_file_info = 
        
        new_file = open('./test.exe', 'wb')
        new_file.write(parsed_file.to_binary_data())
        new_file.close()
        print("End")

if __name__ == "__main__":
        apecker()
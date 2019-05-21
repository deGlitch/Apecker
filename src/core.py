# -*- coding: utf-8 -*-
from lib_pe.core import PortableExecutable
from lib_pe.permission_creator import PermissionsCreator
import packer_structs
import struct 
import zlib

class PackedFileInfo:
        def __init__(self, sections_num, unpacked_data_size, packed_data_size):
                self.__sections_num = sections_num
                self.__unpacked_data_size = unpacked_data_size
                self.__packed_data_size = packed_data_size
        def pack(self):
                return struct.pack(packer_structs.PACKED_FILE_DESCRIPTOR.format, self.__sections_num, self.__unpacked_data_size, self.__packed_data_size)

in_file = "calc32.exe"
out_file = "test.exe"

def apecker():
        print("Start")
        file_content = open(r'C:\\Users\\Parzival\Desktop\\Project\\Apecker\\downloads\\{}'.format(in_file),'rb').read()
        parsed_file = PortableExecutable(file_content)                                        

        # get data about file pre changes

        number_of_sections = len(parsed_file.sections)

        # combine all headers and data
        
        combined_headers_buffer = b''
        combined_data_buffer = b''

        for section in parsed_file.sections:
                combined_headers_buffer += section.header.pack()
                combined_data_buffer += section.data

        # compress 

        combined_uncompressed_buffer = combined_headers_buffer + combined_data_buffer
        compressed_buffer = zlib.compress(combined_uncompressed_buffer)

        # create packed file info

        packed_file_info = PackedFileInfo(number_of_sections, len(combined_uncompressed_buffer), len(compressed_buffer))

        packed_section_data = packed_file_info.pack() + compressed_buffer

        # remove all previous sections
        
        # parsed_file.remove_all_sections()

        # change imports
        
        #parsed_file.imported_modules = parsed_file.imported_modules[1:]

        # add a new packed section (use the unpacked data size as the virtual size so we could unpack it in memory later)

        #parsed_file.add_section('.apacked', packed_section_data, PermissionsCreator.create(), virtual_size=len(combined_uncompressed_buffer))    
        
        new_file = open('C:\\Users\\Parzival\Desktop\\Project\\Apecker\\downloads\\{}'.format(out_file), 'wb')
        new_file.write(parsed_file.to_binary_data())
        new_file.close()
        print("End")

if __name__ == "__main__":
        apecker()
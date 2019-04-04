# -*- coding: utf-8 -*-
import lib_pe

def apecker():
        file_content = open(r'C:\\Users\\Parzival\Desktop\\Project\\Apecker\\test_executables\\calc32.exe','rb').read()
        parsed_file = lib_pe.PortableExecutable(file_content)
        text_section_data = parsed_file.getSection('.text')

        print('the start of the nt header is {}'.format(parsed_file.dos_header.e_lfanew))

if __name__ == "__main__":
        apecker()
# -*- coding: utf-8 -*-
from lib_pe.core import PortableExecutable

def apecker():
        print("Start")
        file_content = open(r'C:\\Users\\Parzival\Desktop\\Project\\Apecker\\test_executables\\calc32.exe','rb').read()
        parsed_file = PortableExecutable(file_content)
        text_section = parsed_file.getSection('.text')
        text_section_data = parsed_file.getSectionData('.text')
        print("End")

if __name__ == "__main__":
        apecker()
# -*- coding: utf-8 -*-
from lib_pe.core import PortableExecutable
from lib_pe.permission_creator import PermissionsCreator

def apecker():
        print("Start")
        file_content = open(r'C:\\Users\\Parzival\Desktop\\Project\\Apecker\\downloads\\calc32.exe','rb').read()
        parsed_file = PortableExecutable(file_content)
        parsed_file.add_section(".compressed", b'asafasaf', PermissionsCreator.create())
        
        new_file = open('./test.exe', 'wb')
        new_file.write(parsed_file.to_binary_data())
        new_file.close()
        print("End")

if __name__ == "__main__":
        apecker()
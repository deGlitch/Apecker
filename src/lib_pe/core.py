# -*- coding: utf-8 -*-

# Global Libraries
import struct
from functools import reduce

# Local Libraries
from . import helpers
from . import pe_structs

# Exceptions

class PortableExecutableException(Exception):
    """Basic exception for errors raised by the pe library"""

class NonExistantSectionName(PortableExecutableException):
    """Tried to access section which is non existant"""

# Struct Classes

class DosHeader:
    def __init__(self, content):
        (
            self.e_magic,
            self.e_cblp,
            self.e_cp,
            self.e_crlc,
            self.e_cparhdr,
            self.e_minalloc,
            self.e_maxalloc,
            self.e_ss,
            self.sp,
            self.e_csum,
            self.e_ip,
            self.e_cs,
            self.e_lfarlc,
            self.e_ovno,
            self.e_res,
            self.e_oemid,
            self.e_oeaminfo,
            self.e_res2,
            self.e_lfanew
        ) = struct.unpack(pe_structs.DOS_STRUCT.format, content)
    
    def pack(self) -> bytes:
        return struct.pack(pe_structs.DOS_STRUCT.format,
            self.e_magic,
            self.e_cblp,
            self.e_cp,
            self.e_crlc,
            self.e_cparhdr,
            self.e_minalloc,
            self.e_maxalloc,
            self.e_ss,
            self.sp,
            self.e_csum,
            self.e_ip,
            self.e_cs,
            self.e_lfarlc,
            self.e_ovno,
            self.e_res,
            self.e_oemid,
            self.e_oeaminfo,
            self.e_res2,
            self.e_lfanew)

class ImportedFunction:
    def __init__(self, name = None, ordinal = None):
        self.name = name
        self.ordinal = ordinal

class ImportedModule:
    def __init__(self, name, imported_functions = []):
        self.name = name
        self.imported_functions = imported_functions

class IMAGE_THUNK_DATA32:
    def __init__(self, content=None):
        if content:
            self.name_address= struct.unpack(pe_structs.IMAGE_THUNK_DATA32.format, content)[0]
        else:
            self.name_address = 0
    def is_empty(self):
        return self.name_address == 0
    def is_ordinal(self) -> bool:
        # check if the first bit of the address is 
        return bin(self.name_address).split('b')[1][0] == 1
    
    def pack(self) ->  bytes:
        return struct.pack(pe_structs.IMAGE_THUNK_DATA32.format, self.name_address)

class ImageImportDirectory:
    def __init__(self, content=None):
        if(content):
            (
            self.import_name_list_rva,
            self.timestamp,
            self.forwarder_chain,
            self.module_name_rva,
            self.import_address_list_rva
            ) = struct.unpack(pe_structs.IMAGE_IMPORT_DESCRIPTOR.format, content)
        else:
            self.import_name_list_rva = 0
            self.timestamp = 0
            self.forwarder_chain = 0
            self.module_name_rva = 0
            self.import_address_list_rva = 0
    
    def is_empty(self):
        return self.import_name_list_rva == 0 and self.forwarder_chain == 0 and self.module_name_rva == 0 and self.import_address_list_rva == 0
    def pack(self):
        return struct.pack(pe_structs.IMAGE_IMPORT_DESCRIPTOR.format, self.import_name_list_rva, self.timestamp, self.forwarder_chain, self.module_name_rva, self.import_address_list_rva)
        
class DataDirectory:
    def __init__(self, content):
        (
            self.VirtualAddress,
            self.Size
        ) = struct.unpack(pe_structs.DATA_DIRECTORY.format, content)

    def pack(self) -> bytes:
        return struct.pack(pe_structs.DATA_DIRECTORY.format, self.VirtualAddress, self.Size)

class OptionalHeader32:
    def __init__(self, content):
        (
            self.Magic,
            self.MajorLinkerVersion,
            self.MinorLinkerVersion,
            self.SizeOfCode,
            self.SizeOfInitializedData,
            self.SizeOfUninitializedData,
            self.AddressOfEntryPoint,
            self.BaseOfCode,
            self.BaseOfData,
            self.ImageBase,
            self.SectionAlignment,
            self.FileAlignment,
            self.MajorOperatingSystemVersion,
            self.MinorOperatingSystemVersion,
            self.MajorImageVersion,
            self.MinorImageVersion,
            self.MajorSubsystemVersion,
            self.MinorSubsystemVersion,
            self.Win32VersionValue,
            self.SizeOfImage,
            self.SizeOfHeaders,
            self.CheckSum,
            self.Subsystem,
            self.DLLCharacteristics,
            self.SizeOfStackReserve,
            self.SizeOfStackCommit,
            self.SizeOfHeapReserve,
            self.SizeOfHeapCommit,
            self.LoaderFlags,
            self.NumberOfRvaAndSizes,
            data_directories_content
        ) = struct.unpack(pe_structs.OPTIONAL_HEADER_32.format, content)

        self.DataDirectory = list(map(lambda group: DataDirectory(
            bytes(group)), helpers.grouper(data_directories_content, 8)))

    def stripDataDirectory(self):
        for i in range(0, len(DataDirectory)):
            self.DataDirectory[i].VirtualAddress = 0
            self.DataDirectory[i].Size = 0

    def pack(self) -> bytes:
        packed_data_directories = list(map(lambda directory: directory.pack(), self.DataDirectory))
        data_directories_content = reduce(lambda packed_directory1, packed_directory2: packed_directory1 + packed_directory2, packed_data_directories)
        return struct.pack(pe_structs.OPTIONAL_HEADER_32.format,
                           self.Magic,
                           self.MajorLinkerVersion,
                           self.MinorLinkerVersion,
                           self.SizeOfCode,
                           self.SizeOfInitializedData,
                           self.SizeOfUninitializedData,
                           self.AddressOfEntryPoint,
                           self.BaseOfCode,
                           self.BaseOfData,
                           self.ImageBase,
                           self.SectionAlignment,
                           self.FileAlignment,
                           self.MajorOperatingSystemVersion,
                           self.MinorOperatingSystemVersion,
                           self.MajorImageVersion,
                           self.MinorImageVersion,
                           self.MajorSubsystemVersion,
                           self.MinorSubsystemVersion,
                           self.Win32VersionValue,
                           self.SizeOfImage,
                           self.SizeOfHeaders,
                           self.CheckSum,
                           self.Subsystem,
                           self.DLLCharacteristics,
                           self.SizeOfStackReserve,
                           self.SizeOfStackCommit,
                           self.SizeOfHeapReserve,
                           self.SizeOfHeapCommit,
                           self.LoaderFlags,
                           self.NumberOfRvaAndSizes,
                           data_directories_content)
    
class FileHeader:
    def __init__(self, content):
        (
            self.Machine,
            self.NumberOfSections,
            self.TimeDataStamp,
            self.PointerToSymbolTable,
            self.NumberOfSymbols,
            self.SizeOfOptionalHeader,
            self.Characteristics
        ) = struct.unpack(pe_structs.FILE_HEADER.format, content)
    def pack(self) -> bytes:
        return struct.pack(pe_structs.FILE_HEADER.format,
                           self.Machine,
                           self.NumberOfSections,
                           self.TimeDataStamp,
                           self.PointerToSymbolTable,
                           self.NumberOfSymbols,
                           self.SizeOfOptionalHeader,
                           self.Characteristics)

class NtHeader:
    def __init__(self, content):
        (
            self.Signature,
            file_header_content,
            optional_header_content
        ) = struct.unpack(pe_structs.NT_HEADER.format, content)

        self.FileHeader = FileHeader(file_header_content)
        self.OptionalHeader = OptionalHeader32(optional_header_content)
    
    def pack(self) -> bytes:
        return struct.pack(pe_structs.NT_HEADER.format, self.Signature, self.FileHeader.pack(), self.OptionalHeader.pack())
# an abstract section containing the header and the data
class Section:
    def __init__(self, header, data):
        self.header = header
        self.data = data

# a straight mapping of a section header from the pe format
class SectionHeader:

    def __init__(self, content = None):
        if content is not None:
            (
            self.Name,
            self.VirtualSize,
            self.VirtualAddress,
            self.SizeOfRawData,
            self.PointerToRawData,
            self.PointerToRelocations,
            self.PointerToLineNumbers,
            self.NumberOfRelocations,
            self.NumberOfLineNumbers,
            self.Characteristics
            ) = struct.unpack(pe_structs.SECTION_HEADER.format, content)
            self.FormmatedName = self.Name.replace(b'\x00',b'')

    def pack(self) -> bytes:
        return struct.pack(pe_structs.SECTION_HEADER.format, 
            self.Name,
            self.VirtualSize,
            self.VirtualAddress,
            self.SizeOfRawData,
            self.PointerToRawData,
            self.PointerToRelocations,
            self.PointerToLineNumbers,
            self.NumberOfRelocations,
            self.NumberOfLineNumbers,
            self.Characteristics)

    def setup(self, name, virtual_size, raw_size, chracteristics, virtual_address = 0, raw_address = 0 , relocations_pointer = 0, line_numbers_pointer = 0, relocations_number = 0, line_numbers_number = 0):
        self.Name = bytes(name, "utf-8")
        self.VirtualSize = virtual_size
        self.VirtualAddress = virtual_address
        self.SizeOfRawData = raw_size
        self.PointerToRawData = raw_address
        self.PointerToRelocations = relocations_pointer
        self.PointerToLineNumbers = line_numbers_pointer
        self.NumberOfRelocations = relocations_number
        self.NumberOfLineNumbers = line_numbers_number
        self.Characteristics = chracteristics

class PortableExecutable:
    def __init__(self, content):
        self.__original_data = content

        # DOS Header
        self.dos_header = DosHeader(content[:pe_structs.DOS_STRUCT.size])

        # NT Header
        nt_header_end = self.dos_header.e_lfanew + pe_structs.NT_HEADER.size
        self.nt_header = NtHeader(content[self.dos_header.e_lfanew: nt_header_end])

        # Sections
        sections_headers_start_address = nt_header_end
        sections_headers_end_address = sections_headers_start_address + (pe_structs.SECTION_HEADER.size * self.nt_header.FileHeader.NumberOfSections)
        section_headers_data_groups = helpers.grouper(content[sections_headers_start_address: sections_headers_end_address], pe_structs.SECTION_HEADER.size)

        self.sections = []
        for group in section_headers_data_groups:

            # parse out the section header
            header = SectionHeader(bytes(group))

            # from the section header calculate where the section data start and end addresses are
            data_start_address = header.PointerToRawData
            data_end_address = header.PointerToRawData + header.SizeOfRawData

            # save the section data from the addresses calculated
            data = content[data_start_address : data_end_address]
            
            # insert the new section at the end of the list
            self.sections.insert(len(self.sections), Section(header, data))

        # Import Data Directory
        import_data_directory_rva = self.nt_header.OptionalHeader.DataDirectory[1].VirtualAddress

        # get the file address of the import directory by offsetting the raw 
        # address of the section with the absolute offset created from the rva
        # find all the import module directory image structs
        import_directory_images = []
        import_directory_file_address = self.__convert_rva_to_raw_address(import_data_directory_rva)
        file_offset = import_directory_file_address
        while(True):
            image_import_directory = ImageImportDirectory(content[file_offset : file_offset + pe_structs.IMAGE_IMPORT_DESCRIPTOR.size])
            if image_import_directory.is_empty():
                break
            import_directory_images.append(image_import_directory)
            file_offset += pe_structs.IMAGE_IMPORT_DESCRIPTOR.size
        
        self.imported_modules = []
        for image in import_directory_images:
            name_file_address = self.__convert_rva_to_raw_address(image.module_name_rva)

            # get module name
            name = helpers.read_until_null_byte(content[name_file_address:])

            imported_functions = []

            # get module functions
            name_list_offset =  self.__convert_rva_to_raw_address(image.import_name_list_rva)

            while(True):
                thunk_entry = IMAGE_THUNK_DATA32(content[name_list_offset: name_list_offset + pe_structs.IMAGE_THUNK_DATA32.size])
                if thunk_entry.is_empty():
                    break
                
                #TODO: add usage of ordinals check
                function_name_struct_file_offset = self.__convert_rva_to_raw_address(thunk_entry.name_address)
                function_name_file_offset = function_name_struct_file_offset + 2 # there is a HINT(WORD) before the actual name
                function_name = helpers.read_until_null_byte(content[function_name_file_offset:])
                imported_functions.append(ImportedFunction(name=function_name))

                name_list_offset += pe_structs.IMAGE_THUNK_DATA32.size
            
            self.imported_modules.append(ImportedModule(name, imported_functions))

    def __get_section_by_address(self, address, is_virtual=False):
        # find the section in which the address of the import directory lies
        section_of_address = None
        for section in self.sections:
            if is_virtual:
                if address <= section.header.VirtualAddress + section.header.VirtualSize:
                    section_of_address = section
                    break
            else:
                if address <= section.header.PointerToRawData + section.header.SizeOfRawData:
                    section_of_address = section
                    break
         
        if section_of_address is None:
            raise Excpetion("failde to convert rva to raw address")
        return section

    def __convert_rva_to_raw_address(self, rva):
        section = self.__get_section_by_address(rva, is_virtual=True)
        return rva - section.header.VirtualAddress + section.header.PointerToRawData

    def __convert_raw_address_to_rva(self, raw_address):
        # find the section in which the address of the import directory lies
        section = self.__get_section_by_address(rva, is_virtual=False)
        return raw_address - section.header.PointerToRawData + section.header.VirtualAddress

    def __rebuild_import_directory(self):

        # get the section the import directory lies in
        import_data_directory_rva = self.nt_header.OptionalHeader.DataDirectory[1].VirtualAddress
        import_data_directory_section = self.__get_section_by_address(import_data_directory_rva, is_virtual=True)
        import_directory_offset_from_section_start = import_data_directory_rva - import_data_directory_section.header.VirtualAddress

        base_virtual_address = import_data_directory_rva
        
        imported_modules_count = len(self.imported_modules)
        imported_functions_count = sum(map(lambda module: len(module.imported_functions), self.imported_modules))


        imported_module_names = []
        imported_function_names = []
        for module in self.imported_modules:
            imported_module_names.append(module.name)
            for function in module.imported_functions:
                imported_function_names.append(function.name)
        
        # add 1 for the null entries
        NULL_ENTRY = 1
        NULL_ENTRIES_PER_MODULE = 1 * imported_modules_count
        directory_import_tables_overall_size =  (imported_modules_count + NULL_ENTRY) * pe_structs.IMAGE_IMPORT_DESCRIPTOR.size
        import_lookup_tables_overall_size =  (imported_functions_count + NULL_ENTRIES_PER_MODULE ) * pe_structs.IMAGE_THUNK_DATA32.size

        NULL_BYTE_SIZE = 1
        HINT_BYTES_SIZE = 2

        function_names_overall_size = sum(map(lambda name: len(name) + NULL_BYTE_SIZE + HINT_BYTES_SIZE, imported_function_names))
        module_names_overall_size = sum(map(lambda name: len(name) + NULL_BYTE_SIZE, imported_module_names))
        hint_table_overall_size = function_names_overall_size + module_names_overall_size

        overall_directory_size = directory_import_tables_overall_size + import_lookup_tables_overall_size + hint_table_overall_size

        directory_data = [b'\x00'] * overall_directory_size
    
        # start setting the data in the right place

        # hints first

        hints_offset_table = {}
        hints_offset = directory_import_tables_overall_size + import_lookup_tables_overall_size
        for name in imported_function_names:
            hints_offset_table[name] = hints_offset
            data_to_write = b'\x00\x00' + name + b'\x00' # add the hint to the name and finish it with a null terminator
            helpers.copy_to_list(hints_offset, data_to_write, directory_data)
            hints_offset += len(data_to_write)

        for name in imported_module_names:
            hints_offset_table[name] = hints_offset
            data_to_write = name + b'\x00' # name and finish it with a null terminator
            helpers.copy_to_list(hints_offset, data_to_write, directory_data)
            hints_offset += len(data_to_write)


        # thunks

        thunks_start_offset_table = {}
        thunk_offset = directory_import_tables_overall_size
        count = 0
        for module in self.imported_modules:
            thunks_start_offset_table[module.name] = thunk_offset # save the start of a module thunk array
            for function in module.imported_functions:
                count+=1
                thunk = IMAGE_THUNK_DATA32()
                thunk.name_address = hints_offset_table[function.name] + base_virtual_address # get the hint offset from the hint offset table
                helpers.copy_to_list(thunk_offset, thunk.pack(), directory_data)
                thunk_offset += pe_structs.IMAGE_THUNK_DATA32.size # offset the currant thunk pointer
            
            # add the null thunk
            thunk = IMAGE_THUNK_DATA32()
            helpers.copy_to_list(thunk_offset, thunk.pack(), directory_data)
            thunk_offset += pe_structs.IMAGE_THUNK_DATA32.size
        
        # modules

        module_offset = 0
        for module in self.imported_modules:
            directory = ImageImportDirectory()
            directory.module_name_rva = hints_offset_table[module.name] + base_virtual_address # update the hint rva with the new offset from the hints offset table
            directory.import_address_list_rva = thunks_start_offset_table[module.name] + base_virtual_address
            directory.import_name_list_rva = thunks_start_offset_table[module.name] + base_virtual_address

            # write the directory to the data
            helpers.copy_to_list(module_offset, directory.pack(), directory_data)

            module_offset += pe_structs.IMAGE_IMPORT_DESCRIPTOR.size

        # update the new section data
        section_index = self.get_section_index(import_data_directory_section.header.FormmatedName)

        directory_data = import_directory_offset_from_section_start * [b'\x00'] + directory_data
        self.sections[section_index].data = reduce(lambda byte1,byte2: byte1 + byte2, directory_data)

    def get_size(self):
        last_section_header = self.sections[-1].header
        return last_section_header.PointerToRawData + last_section_header.SizeOfRawData

    def to_binary_data(self):
        # rebuild pe directories

        self.__rebuild_import_directory()
        self.__recalculate_section_addresses()

        ## write data

        data = [b'\x00'] * self.get_size()

        # dos header
        helpers.copy_to_list(0, self.dos_header.pack(), data)

        # nt header
        helpers.copy_to_list(self.dos_header.e_lfanew, self.nt_header.pack(), data)

        # sections
        nt_header_end = self.dos_header.e_lfanew + pe_structs.NT_HEADER.size
        for index in range(0, len(self.sections)):
            section_header_start_address = nt_header_end + (index * pe_structs.SECTION_HEADER.size)
            section = self.sections[index]
            helpers.copy_to_list(section_header_start_address, section.header.pack(), data)
            helpers.copy_to_list(section.header.PointerToRawData, section.data, data)

        binary_data = reduce(lambda byte1,byte2: byte1 + byte2, data)
        return binary_data

    # Sections

    def __recalculate_section_addresses(self):
        file_alignment = self.nt_header.OptionalHeader.FileAlignment
        section_alignment = self.nt_header.OptionalHeader.SectionAlignment

        # the sections data address start lies at the end of the section headers (aligned to file)
        sections_headers_start_address = self.dos_header.e_lfanew + pe_structs.NT_HEADER.size
        sections_data_start_address = sections_headers_start_address + (pe_structs.SECTION_HEADER.size * self.nt_header.FileHeader.NumberOfSections)

        

        for section_index in range(0, len(self.sections)):

            # recalculate section raw size
            aligned_new_file_size = helpers.alignAddress(len(self.sections[section_index].data), file_alignment)
            self.sections[section_index].header.SizeOfRawData = aligned_new_file_size

            new_unaligned_raw_address = None
            new_unaligned_virtual_address = None
            
            if section_index == 0:
                # first section - use the end of the sections headers as the base address
                new_unaligned_raw_address = sections_data_start_address
                new_unaligned_virtual_address = sections_data_start_address
            else:
                # other sections - get the last section raw and virtual ending addresses (start + size)
                last_section_header = self.sections[section_index-1].header
                new_unaligned_raw_address = last_section_header.PointerToRawData + last_section_header.SizeOfRawData
                new_unaligned_virtual_address = last_section_header.VirtualAddress + last_section_header.VirtualSize

            # update the currant section with the new addresses
            self.sections[section_index].header.PointerToRawData = helpers.alignAddress(new_unaligned_raw_address, file_alignment)
            self.sections[section_index].header.VirtualAddress = helpers.alignAddress(new_unaligned_virtual_address, section_alignment)

    def get_section_index(self, name):
        for index in range(len(self.sections)):
            section = self.sections[index]
            if section.header.FormmatedName == name:
                return index
        raise NonExistantSectionName()

    def get_section(self, name):
        for section in self.sections:
            if section.header.FormmatedName == name:
                return section
        raise NonExistantSectionName()

    def remove_section(self, name):
        for index in range(len(self.sections)):
            section = self.sections[index]
            if section.header.FormmatedName == name:
                del self.sections[index]
                self.nt_header.FileHeader.NumberOfSections -= 1
                self.__recalculate_section_addresses()
                return
        raise NonExistantSectionName()
            
    def remove_all_sections(self):
        for index in range(len(self.sections)):
            del self.sections[0]
        self.nt_header.FileHeader.NumberOfSections = 0

    def add_section(self, name, data, permissions, raw_size = None, virtual_size = None):

        # calculate the raw size of the new section
        file_alignment = self.nt_header.OptionalHeader.FileAlignment
        new_raw_size = None
        if raw_size is None:
            new_raw_size = helpers.alignAddress(len(data), file_alignment)            
        else:
            new_raw_size = helpers.alignAddress(size, file_alignment)
            
        # calculate the virtual size of the new section
        new_virtual_size = None

        if virtual_size is None:
            new_virtual_size = len(data)
        else:
            new_virtual_size = virtual_size        
        
        # create the new header
        new_header = SectionHeader()
        new_header.setup(name, new_virtual_size, new_raw_size, permissions)

        # create the new section
        new_section = Section(new_header, data)

        # add the new section to the end of the sections list
        self.sections.append(new_section)

        self.nt_header.FileHeader.NumberOfSections += 1

        # recalculate the file addresses
        self.__recalculate_section_addresses()
            
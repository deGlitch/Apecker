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
    
    def pack(self):
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

class DataDirectory:
    def __init__(self, content):
        (
            self.VirtualAddress,
            self.Size
        ) = struct.unpack(pe_structs.DATA_DIRECTORY.format, content)

    def pack(self):
        return struct.pack(pe_structs.DATA_DIRECTORY.format,
                           self.VirtualAddress,
                           self.Size)

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
        #TODO: implement
        pass

    def pack(self):
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
    def pack(self):
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
    
    def pack(self):
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

    def pack(self):
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

    def get_size(self):
        last_section_header = self.sections[-1].header
        return last_section_header.PointerToRawData + last_section_header.SizeOfRawData

    def to_binary_data(self):
        data = [b'\x00'] * self.get_size()
        helpers.map_to_list(0, self.dos_header.pack(), data)
        helpers.map_to_list(self.dos_header.e_lfanew, self.nt_header.pack(), data)

        nt_header_end = self.dos_header.e_lfanew + pe_structs.NT_HEADER.size

        for index in range(0, len(self.sections)):
            section_header_start_address = nt_header_end + (index * pe_structs.SECTION_HEADER.size)
            section = self.sections[index]
            helpers.map_to_list(section_header_start_address, section.header.pack(), data)
            helpers.map_to_list(section.header.PointerToRawData, section.data, data)

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

    def get_section(self, name):
        for section in self.sections:
            if helpers.decodeBinaryString(section.header.Name) == name:
                return section
        raise NonExistantSectionName()

    def remove_section(self, name):
        for index in range(len(self.sections)):
            section = self.sections[index]
            if(helper.decodeBinaryString(section.header.Name)) == name:
                del self.sections[index]
                self.nt_header.FileHeader.NumberOfSections -= 1
                self.__recalculate_section_addresses()
                return
        raise NonExistantSectionName()
            
    def remove_all_sections(self):
        for index in range(len(self.sections)):
            del self.sections[0]

    def add_section(self, name, data, permissions, raw_size = None, virtual_size = None, recalculate_addresses = True):

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

        if recalculate_addresses:
            self.__recalculate_section_addresses()
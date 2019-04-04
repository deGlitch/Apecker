# -*- coding: utf-8 -*-

# Global Libraries
import struct

# Local Libraries
import helpers
import pe_structs


# Exceptions

class PortableExecutableException(Exception):
    """Basic exception for errors rasied by the pe library"""


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


class DataDirectory:
    def __init__(self, content):
        (
            self.VirtualAddress,
            self.Size
        ) = struct.unpack(pe_structs.DATA_DIRECTORY.format, content)

    def __str__(self):
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

    def __str__(self):
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
                           self.NumberOfRvaAndSizes)


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

    def __str__(self):
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


class SectionHeader:
    def __init__(self, content):
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


class PortableExecutable:
    def __init__(self, content):
        self.__content__ = content

        # DOS Header
        self.dos_header = DosHeader(content[:pe_structs.DOS_STRUCT.size])

        # NT Header
        nt_header_end = self.dos_header.e_lfanew + pe_structs.NT_HEADER.size
        self.nt_header = NtHeader(
            content[self.dos_header.e_lfanew: nt_header_end])

        # Sections
        sections_start_address = nt_header_end
        sections_end_address = sections_start_address + \
            (pe_structs.SECTION_HEADER.size *
             self.nt_header.FileHeader.NumberOfSections)
        section_headers_data_groups = helpers.grouper(
            content[sections_start_address: sections_end_address], pe_structs.SECTION_HEADER.size)
        self.sections = list(map(lambda group: SectionHeader(bytes(group)), section_headers_data_groups))

    def getSection(self, name):
        for section in self.sections:
            if helpers.decodeBinaryString(section.Name) == name:
                return section
        raise NonExistantSectionName()

    def getSectionData(self, name):
        section = self.getSection(name)
        section_data_start_address = section.PointerToRawData
        section_data_end_address = section_data_start_address + section.SizeOfRawData
        return self.__content__[section_data_start_address: section_data_end_address]

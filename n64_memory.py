from binaryninja import BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics

from .n64_header import N64Header
from .util import *

def define_misc_sections(bv: BinaryView):
    sections = [
        (0x00000000, 0x007FFFFF, "RDRAM", ".rdram"),
        (0x00000000, 0x000003FF, "Interrupt Vector Table",".ivt"),
        (0x03F00000, 0x03F00027, "RDRAM Registers",".rdreg"),
        (0x04000000, 0x0403FFFF, "SP Memory", ".spmem"),
        (0x04000000, 0x04000FFF, "SP Data Memory", ".spdmem"),
        (0x04001000, 0x04001FFF, "SP Instruction Memory", ".spimem"),
        (0x04040000, 0x0404001F, "SP Registers",".spreg"),
        (0x04080000, 0x04080003, "SP_PC_Reg",".spcreg"),
        (0x04100000, 0x0410001F, "DP Command Registers",".dpcreg"),
        (0x04200000, 0x0420000F, "DP Span Registers",".dpsreg"),
        (0x04300000, 0x0430000F, "MIPS Interface (MI) Registers",".mireg"),
        (0x04400000, 0x04400037, "Video Interface (VI) Registers",".vireg"),
        (0x04500000, 0x04500017, "Audio Interface (AI) Registers",".aireg"),
        (0x04600000, 0x04600034, "Peripheral Interface (PI) Registers",".pireg"),
        (0x04700000, 0x0470001F, "RDRAM Interface (RI) Registers",".rireg"),
        (0x04800000, 0x0480001B, "Serial Interface (SI) Registers",".sireg"),
        (0x05000500, 0x0500054B, "N64 Disk Drive (DD) Registers",".ddreg"),
        (0x1FC00000, 0x1FC007BF, "PIF Boot ROM",".pifrom"),
        (0x1FC007C0, 0x1FC007FF, "PIF RAM",".pifram"),
    ]
    for start, end, section_name_long, section_name_short in sections:
        for mips_segment, mips_segment_name in MIPS_SEGMENTS:
            bv.add_auto_section(f"{section_name_short}_{mips_segment_name.lower()}",
                                addr_to_64(start | mips_segment),
                                end - start,
                                SectionSemantics.ExternalSectionSemantics,
                                info_section=f"{section_name_long} ({mips_segment_name})")

def define_segments(bv: BinaryView, raw_bv: BinaryView, load_address: int):
    # rx !w
    flags = (SegmentFlag.SegmentReadable |
            SegmentFlag.SegmentExecutable |
            SegmentFlag.SegmentContainsCode |
            SegmentFlag.SegmentDenyWrite)

    rom_addr = addr_to_64(0xB0000000)
    # Cartridge
    bv.add_auto_segment(rom_addr,
                        raw_bv.length,
                        0,
                        raw_bv.length,
                        flags)
    bv.add_auto_section('.rom',
                        rom_addr,
                        raw_bv.length,
                        SectionSemantics.ReadOnlyCodeSectionSemantics)

    # rwx
    flags = (SegmentFlag.SegmentReadable |
             SegmentFlag.SegmentWritable | 
             SegmentFlag.SegmentExecutable |
             SegmentFlag.SegmentContainsCode)
            
    # Code copied to RAM by IPL3
    ram_code_len = raw_bv.length - N64Header.BOOTLOADER_END
    bv.add_auto_segment(load_address,
                        ram_code_len,
                        N64Header.BOOTLOADER_END,
                        ram_code_len,
                        flags)
    bv.add_auto_section('.ram',
                        load_address,
                        ram_code_len,
                        SectionSemantics.ReadOnlyCodeSectionSemantics)

    # r-x
    flags = (SegmentFlag.SegmentReadable |
             SegmentFlag.SegmentExecutable |
             SegmentFlag.SegmentContainsCode)

    boot_addr = addr_to_64(0xA4000040)
    boot_len = N64Header.BOOTLOADER_END - N64Header.HEADER_SIZE
    bv.add_auto_segment(boot_addr,
                        boot_len,
                        N64Header.HEADER_SIZE,
                        boot_len, 
                        flags)
    bv.add_auto_section('.boot',
                        boot_addr,
                        boot_len,
                        SectionSemantics.ReadOnlyCodeSectionSemantics)


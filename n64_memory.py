from binaryninja import BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics
from binaryninja.log import log_info

from .n64_header import N64Header
from .pif import PIF

def addr_to_64(v):
    if v >> 31:
        return v | (0xFFFFFFFF << 32)
    else:
        return v

CARTRIDGE_BASE = addr_to_64(0xB0000000)

# 0x0000`0000 - 0x7fff`ffff KUSEG, USEG, SUSEG TLB map (User Mode)
KUSEG_BASE = 0x00000000
KUSEG_END  = 0x7FFFFFFF
KUSEG = (KUSEG_BASE, KUSEG_END, "KUSEG")
# 0x8000`0000 - 0x9fff`ffff KSEG0 Direct map (Cached Memory)
KSEG0_BASE = 0x80000000
KSEG0_END  = 0x9FFFFFFF
KSEG0 = (KSEG0_BASE, KSEG0_END, "KSEG0")
# 0xa000`0000 - 0xbfff`ffff KSEG1 Direct map (Non-cached Memory)
KSEG1_BASE = 0xA0000000
KSEG1_END  = 0xBFFFFFFF
KSEG1 = (KSEG1_BASE, KSEG1_END, "KSEG1")
# 0xc000`0000 - 0xdfff`ffff KSSEG, SSEG TLB mapping (Supervisor Mode)
KSSEG_BASE = 0xC0000000
KSSEG_END  = 0xDFFFFFFF
KSSEG = (KSSEG_BASE, KSSEG_END, "KSSEG")
# 0xe000`0000 - 0xffff`ffff KSEG3 TLB mapping (Kernel Mode)
KSEG3_BASE = 0xE0000000
KSEG3_END  = 0xFFFFFFF
KSEG3 = (KSEG3_BASE, KSEG3_END, "KSEG3")

KSEG_MIRRORS = [ KSEG0, KSEG1 ]
KSEGS = [ KUSEG, KSEG0, KSEG1, KSSEG, KSEG3, ]


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
        # Mapped in below
        # (0x1FC00000, 0x1FC007BF, "PIF Boot ROM",".pifrom"),
        (0x1FC007C0, 0x1FC007FF, "PIF RAM",".pifram"),
    ]
    for start, end, section_desc, section_name in sections:
        for kseg, _, kseg_name in KSEG_MIRRORS:
            bv.add_auto_section(f"{section_name}_{kseg_name.lower()}",
                                addr_to_64(start | kseg),
                                end - start,
                                SectionSemantics.ExternalSectionSemantics,
                                info_section=f"{section_desc} ({kseg_name})")

    # Map the PIF rom into our database
    bv.memory_map.add_memory_region(".pifrom", addr_to_64(0x1FC00000), PIF)

def map_file_into_memory(bv: BinaryView,
                                 raw_bv: BinaryView,
                                 load_address: int):
    # read only
    flags = (SegmentFlag.SegmentReadable |
             SegmentFlag.SegmentDenyWrite)

    rom_addr = CARTRIDGE_BASE
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

def define_system_memory_map(bv: BinaryView):
    rwx_seg_flags = (SegmentFlag.SegmentReadable |
                     SegmentFlag.SegmentWritable |
                     SegmentFlag.SegmentExecutable)
    for base, end, name in KSEGS:
        size = end - base + 1
        log_info(
            f'Creating {name} [{base:#08x}-{end:#08x}] ({size} bytes)',
            bv.name
        )
        bv.add_auto_segment(addr_to_64(base), size, 0, 0, rwx_seg_flags)


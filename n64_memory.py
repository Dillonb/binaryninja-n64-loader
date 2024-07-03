from binaryninja import BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics

from .n64_header import N64Header

def define_misc_sections(bv: BinaryView):
    sections = [
        (0xA3F00000, 0xA3F00027, "RDRAM Registers",".rdreg"),
        (0xa4040000, 0xa404001f, "SP Registers",".spreg"),
        (0xa4080000, 0xa4080003, "SP_PC_Reg",".spcreg"),
        (0xA4100000, 0xA410001F, "DP Command Registers",".dpcreg"),
        (0xA4200000, 0xa420000F, "DP Span Registers",".dpsreg"),
        (0xa4300000, 0xa430000F, "MIPS Interface (MI) Registers",".mireg"),
        (0xa4400000, 0xa4400037, "Video Interface (VI) Registers",".vireg"),
        (0xa4500000, 0xa4500017, "Audio Interface (AI) Registers",".aireg"),
        (0xa4600000, 0xa4600034, "Peripheral Interface (PI) Registers",".pireg"),
        (0xa4700000, 0xa470001F, "RDRAM Interface (RI) Registers",".rireg"),
        (0xa4800000, 0xa480001b, "Serial Interface (SI) Registers",".sireg"),
        (0xa5000500, 0xa500054b, "N64 Disk Drive (DD) Registers",".ddreg"),
        (0x1FC00000, 0x1FC007BF, "PIF Boot ROM",".pifrom"),
        (0x1FC007C0, 0x1FC007FF, "PIF RAM",".pifram"),
        (0x80000000, 0x800003FF, "Interrupt Vector Table",".ivt"),
    ]
    for s in sections:
        bv.add_auto_section(s[3], s[0], s[1] - s[0], info_section=s[2])

def define_segments(bv: BinaryView, raw_bv: BinaryView, load_address: int):
    # rx !w
    flags = (SegmentFlag.SegmentReadable |
            SegmentFlag.SegmentExecutable |
            SegmentFlag.SegmentContainsCode |
            SegmentFlag.SegmentDenyWrite)

    rom_addr = 0xFFFFFFFFB0000000
    # Cartridge
    bv.add_auto_segment(rom_addr,
                        raw_bv.length,
                        0,
                        raw_bv.length,
                        flags)
    bv.add_auto_section('.rom', rom_addr, raw_bv.length)

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
    bv.add_auto_section('.ram', load_address, ram_code_len)

    boot_addr = 0xA4000040
    boot_len = N64Header.BOOTLOADER_END - N64Header.HEADER_SIZE
    bv.add_auto_segment(boot_addr,
                        boot_len,
                        N64Header.HEADER_SIZE,
                        boot_len, 
                        SegmentFlag.SegmentContainsCode)
    bv.add_auto_section('.boot', boot_addr, boot_len)


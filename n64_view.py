from binaryninja.types import Type, StructureBuilder
from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, Endianness

import zlib


class N64Header:
    Z64_MAGIC = b"\x80\x37\x12\x40"
    N64_MAGIC = b"\x40\x12\x37\x80"
    V64_MAGIC = b"\x37\x80\x40\x12"

    CHECKSUM_CIC_7102      = 0xEC8B1325
    CHECKSUM_CIC_6101      = 0x1DEB51A9
    CHECKSUM_CIC_6102_7101 = 0xC08E5BD6
    CHECKSUM_CIC_6103_7103 = 0x03B8376A
    CHECKSUM_CIC_6105_7105 = 0xCF7F41DC
    CHECKSUM_CIC_6106_7106 = 0xD1059C6A

    HEADER_SIZE = 0x40
    BOOTLOADER_END = 0x1000

    def create_header_type(self, bv):
        """
        https://github.com/Dillonb/n64/blob/2b198e399222dbbe7accb49f63febd488ed87b5a/src/mem/n64rom.h#L7-L24
        typedef struct n64_header {
            u8 initial_values[4];
            u32 clock_rate;
            u32 program_counter;
            u32 release;
            u32 crc1;
            u32 crc2;
            u64 unknown;
            char image_name[20];
            u32 unknown2;
            u32 manufacturer_id;
            u16 cartridge_id;
            union {
                char country_code[2];
                uint16_t country_code_int;
            };
            u8 boot_code[4032];
        """
        header_builder = StructureBuilder.create()
        init_values = Type.array(Type.int(1, False), 4)
        header_builder.add_member_at_offset("initial_values", init_values, 0)
        header_builder.add_member_at_offset("clock_rate", Type.int(4, False), 4)
        header_builder.add_member_at_offset("program_counter", Type.int(4, False), 8)
        header_builder.add_member_at_offset("release_address", Type.int(4, False), 0xc)
        header_builder.add_member_at_offset("crc1", Type.int(4, False), 0x10)
        header_builder.add_member_at_offset("crc2", Type.int(4, False), 0x14)
        image_name = Type.array(Type.char(), 20)
        header_builder.add_member_at_offset("image_name", image_name, 0x20)
        header_builder.add_member_at_offset("manufacturer_id", Type.int(4, False), 0x38)
        header_builder.add_member_at_offset("cartridge_id", Type.int(2, False), 0x3c)
        country_code = Type.union([
            (Type.array(Type.char(), 2), "country_code"),
            (Type.int(2, False), "country_code_int"),
        ])
        header_builder.add_member_at_offset("country_code", country_code, 0x3e)
        header_struct = Type.structure_type(header_builder)
        name = "n64_header"
        id = Type.generate_auto_type_id("n64", name)
        bv.define_type(id, name, header_struct)
        if addr := bv.get_address_for_data_offset(0):
            bv.define_data_var(addr, name, "header")

    def __init__(self, bv: BinaryView):
        self.parent = bv
        self.magic = bv.read(0, 4)

        match self.magic:
            case N64Header.Z64_MAGIC:
                self.rom_type = "z64"
            case N64Header.N64_MAGIC:
                self.rom_type = "n64"
            case N64Header.V64_MAGIC:
                self.rom_type = "v64"
            case _:
                self.rom_type = "unknown"

        self.load_address = bv.read_int(8, 4) | 0xFFFFFFFF00000000

        self.bootloader = bv.read(N64Header.HEADER_SIZE, 0x9C0)
        self.bootloader_crc32 = zlib.crc32(self.bootloader)

        match self.bootloader_crc32:
            case N64Header.CHECKSUM_CIC_7102:
                self.cic_type = "7102"
            case N64Header.CHECKSUM_CIC_6101:
                self.cic_type = "6101"
            case N64Header.CHECKSUM_CIC_6102_7101:
                self.cic_type = "6102_7101"
            case N64Header.CHECKSUM_CIC_6103_7103:
                self.cic_type = "6103_7103"
                self.load_address -= 0x100000
            case N64Header.CHECKSUM_CIC_6105_7105:
                self.cic_type = "6105_7105"
                pass
            case N64Header.CHECKSUM_CIC_6106_7106:
                self.cic_type = "6106_7106"
                self.load_address -= 0x200000
            case _:
                self.cic_type = "unknown"

        self.title = bv.read(0x20, 0x14).decode("ascii")

    def is_valid(self):
        if (self.rom_type is not None
                and self.rom_type != "unknown"
                and self.cic_type is not None
                and self.cic_type != "unknown"):
            return True
        else:
            return False


class N64View(BinaryView):
    name = "n64"
    long_name = "Nintendo 64 ROM"

    @classmethod
    def is_valid_for_data(cls, bv: BinaryView) -> bool:
        # TODO: support libdragon open source IPL3

        header = N64Header(bv)
        if header.is_valid():
            print(f"This is a {header.rom_type} N64 ROM!")
            print(header.title)
        return header.is_valid()

    def __init__(self, data: BinaryView):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data
        self.header = N64Header(data)
        self.load_address = self.header.load_address
        self._endianness = Endianness.BigEndian

    def init(self) -> bool:
        self.platform = Architecture["mips64"].standalone_platform

        # Cartridge
        self.add_auto_segment(0xFFFFFFFFB0000000,
                              self.raw.length,
                              0,
                              self.raw.length,
                              SegmentFlag.SegmentReadable)

        # Code copied to RAM by IPL3
        self.add_auto_segment(self.header.load_address,
                              self.raw.length - N64Header.BOOTLOADER_END,
                              N64Header.BOOTLOADER_END,
                              self.raw.length - N64Header.BOOTLOADER_END,
                              SegmentFlag.SegmentReadable |
                                  SegmentFlag.SegmentWritable |
                                  SegmentFlag.SegmentExecutable |
                                  SegmentFlag.SegmentContainsCode)

        # TODO define sections

        self.add_entry_point(self.header.load_address)
        self.header.create_header_type(self)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.header.load_address

    def perform_get_default_endianness(self):
        return Endianness.BigEndian

    def perform_get_address_size(self):
        return 64

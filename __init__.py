from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, Endianness

import zlib

Z64_MAGIC = b"\x80\x37\x12\x40"
N64_MAGIC = b"\x40\x12\x37\x80"
V64_MAGIC = b"\x37\x80\x40\x12"

CHECKSUM_CIC_7102      = 0xEC8B1325
CHECKSUM_CIC_6101      = 0x1DEB51A9
CHECKSUM_CIC_6102_7101 = 0xC08E5BD6
CHECKSUM_CIC_6103_7103 = 0x03B8376A
CHECKSUM_CIC_6105_7105 = 0xCF7F41DC
CHECKSUM_CIC_6106_7106 = 0xD1059C6A

mips64 = Architecture['mips64']
# mips64.address_size = 32

class N64Header:
    def __init__(self, data:BinaryView):
        self.magic = data.read(0, 4)

        if self.magic == Z64_MAGIC:
            self.rom_type = "z64"
        elif self.magic == N64_MAGIC:
            self.rom_type = "n64"
        elif self.magic == V64_MAGIC:
            self.rom_type = "v64"
        else:
            self.rom_type = "unknown"


        self.load_address = int.from_bytes(data.read(8, 4)) | 0xFFFFFFFF00000000

        self.bootloader = data.read(0x40, 0x9C0)
        self.bootloader_crc32 = zlib.crc32(self.bootloader)

        if self.bootloader_crc32 == CHECKSUM_CIC_7102:
            self.cic_type = "7102"
        elif self.bootloader_crc32 == CHECKSUM_CIC_6101:
            self.cic_type = "6101"
        elif self.bootloader_crc32 == CHECKSUM_CIC_6102_7101:
            self.cic_type = "6102_7101"
        elif self.bootloader_crc32 == CHECKSUM_CIC_6103_7103:
            self.cic_type = "6103_7103"
            self.load_address -= 0x100000
        elif self.bootloader_crc32 == CHECKSUM_CIC_6105_7105:
            self.cic_type = "6105_7105"
            pass
        elif self.bootloader_crc32 == CHECKSUM_CIC_6106_7106:
            self.cic_type = "6106_7106"
            self.load_address -= 0x200000
        else:
            self.cic_type = "unknown"

        self.title = data.read(0x20, 0x14).decode("ascii")

    def is_valid(self):
        if self.rom_type is not None \
                and self.rom_type != "unknown" \
                and self.cic_type is not None \
                and self.cic_type != "unknown":
            return True
        else:
            return False


class N64View(BinaryView):
    name = "n64"
    long_name = "Nintendo 64 ROM"


    def __init__(self, data:BinaryView):
        BinaryView.__init__(self, parent_view = data, file_metadata=data.file)
        self.platform = mips64.standalone_platform
        self.raw = data
        self.header = N64Header(data)
        self._endianness = Endianness.BigEndian

        if self.header.is_valid():
            print("This is a " + self.header.rom_type + " N64 ROM!")
            print(self.header.title)

    @classmethod
    def is_valid_for_data(cls, data:BinaryView) -> bool:
        # TODO: support libdragon open source IPL3

        header = N64Header(data)
        return header.is_valid()

    def init(self) -> bool:
        # Cartridge
        self.add_auto_segment(0xFFFFFFFFB0000000, self.raw.length, 0, self.raw.length, SegmentFlag.SegmentReadable)
        # Code copied to RAM by IPL3
        self.add_auto_segment(self.header.load_address, self.raw.length - 0x1000, 0x1000, self.raw.length - 0x1000,
                              SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode)
        self.add_entry_point(self.header.load_address)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.header.load_address

    def perform_get_default_endianness(self):
        return Endianness.BigEndian

    def perform_get_address_size(self):
        return 64

N64View.register()

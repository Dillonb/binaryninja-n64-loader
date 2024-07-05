from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, Endianness

from .n64_header import N64Header
from . import n64_symbols, n64_memory


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
        self.platform = Architecture["mips64"].standalone_platform
        self.raw = data
        self.header = N64Header(data)
        self.load_address = self.header.load_address
        self._endianness = Endianness.BigEndian

    def init(self) -> bool:
        n64_memory.define_segments(self, self.raw, self.load_address)
        n64_memory.define_misc_sections(self)

        self.header.create_header_type(self)
        n64_symbols.define_n64_symbols(self, self.load_address)
        # self.add_entry_point(self.load_address)

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.load_address

    def perform_get_default_endianness(self):
        return Endianness.BigEndian

    def perform_get_address_size(self):
        return 64


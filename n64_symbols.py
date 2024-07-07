from binaryninja import BinaryView, Symbol, SymbolType

from .util import *

# Code normally executed out of cached memory
STATIC_CODE_SYMBOLS = [
    Symbol(SymbolType.FunctionSymbol, 0x00000000, "TLB_REFILL"),
    Symbol(SymbolType.FunctionSymbol, 0x00000080, "XTLB_REFILL"),
    Symbol(SymbolType.FunctionSymbol, 0x00000100, "CACHE_ERROR"),
    Symbol(SymbolType.FunctionSymbol, 0x00000180, "GEN_EXCEPTION"),
    Symbol(SymbolType.FunctionSymbol, 0x00000300, "NTSC_PAL"),
    Symbol(SymbolType.FunctionSymbol, 0x00000304, "CART_DD"),
    Symbol(SymbolType.FunctionSymbol, 0x00000308, "ROM_BASE"),
    Symbol(SymbolType.FunctionSymbol, 0x0000030C, "RESET"),
    Symbol(SymbolType.FunctionSymbol, 0x00000310, "CIC_ID"),
    Symbol(SymbolType.FunctionSymbol, 0x00000314, "VERSION"),
    Symbol(SymbolType.FunctionSymbol, 0x00000318, "RDRAM_SIZE"),
    Symbol(SymbolType.FunctionSymbol, 0x0000031C, "NMI_BUFFER"),
]

# Code normally executed out of uncached memory
STATIC_CODE_SYMBOLS_UNCACHED = [
    Symbol(SymbolType.FunctionSymbol, 0x04000040, "bootMain"),
    Symbol(SymbolType.FunctionSymbol, 0x1FC00000, "pifMain"),
]

# Symbol(sym_type, addr, short_name, full_name=None, raw_name=None, binding=None, namespace=None, ordinal=0)
# MMIO registers: accessed uncached
MMIO = [
    Symbol(SymbolType.ExternalSymbol, 0x03F00000, "RDRAM_CONFIG"),
    Symbol(SymbolType.ExternalSymbol, 0x03F00004, "RDRAM_DEVICE_ID"),
    Symbol(SymbolType.ExternalSymbol, 0x03F00008, "RDRAM_DELAY"),
    Symbol(SymbolType.ExternalSymbol, 0x03F0000C, "RDRAM_MODE"),
    Symbol(SymbolType.ExternalSymbol, 0x03F00010, "RDRAM_REF_INTERVAL"),
    Symbol(SymbolType.ExternalSymbol, 0x03F00014, "RDRAM_REF_ROW"),
    Symbol(SymbolType.ExternalSymbol, 0x03F00018, "RDRAM_RAS_INTERVAL"),
    Symbol(SymbolType.ExternalSymbol, 0x03F0001C, "RDRAM_MIN_INTERVAL"),
    Symbol(SymbolType.ExternalSymbol, 0x03F00020, "RDRAM_ADDR_SELECT"),
    Symbol(SymbolType.ExternalSymbol, 0x03F00024, "RDRAM_DEVICE_MANUF"),
    Symbol(SymbolType.ExternalSymbol, 0x04040000, "SP_MEM_ADDR"),
    Symbol(SymbolType.ExternalSymbol, 0x04040004, "SP_DRAM_ADDR"),
    Symbol(SymbolType.ExternalSymbol, 0x04040008, "SP_RD_LEN"),
    Symbol(SymbolType.ExternalSymbol, 0x0404000C, "SP_WR_LEN"),
    Symbol(SymbolType.ExternalSymbol, 0x04040010, "SP_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x04040014, "SP_DMA_FULL"),
    Symbol(SymbolType.ExternalSymbol, 0x04040018, "SP_DMA_BUSY"),
    Symbol(SymbolType.ExternalSymbol, 0x0404001C, "SP_SEMAPHORE"),
    Symbol(SymbolType.ExternalSymbol, 0x04080000, "SP_PC"),
    Symbol(SymbolType.ExternalSymbol, 0x04100000, "DCP_START"),
    Symbol(SymbolType.ExternalSymbol, 0x04100004, "DCP_END"),
    Symbol(SymbolType.ExternalSymbol, 0x04100008, "DCP_CURRENT"),
    Symbol(SymbolType.ExternalSymbol, 0x0410000C, "DCP_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x04100010, "DCP_CLOCK"),
    Symbol(SymbolType.ExternalSymbol, 0x04100014, "DCP_BUFBUSY"),
    Symbol(SymbolType.ExternalSymbol, 0x04100018, "DCP_PIPEBUSY"),
    Symbol(SymbolType.ExternalSymbol, 0x0410001C, "DCP_START"),
    Symbol(SymbolType.ExternalSymbol, 0x04300000, "MI_INIT_MODE"),
    Symbol(SymbolType.ExternalSymbol, 0x04300004, "MI_VERSION"),
    Symbol(SymbolType.ExternalSymbol, 0x04300008, "MI_INTR"),
    Symbol(SymbolType.ExternalSymbol, 0x0430000C, "MI_INTR_MASK"),
    Symbol(SymbolType.ExternalSymbol, 0x04400000, "VI_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x04400004, "VI_ORIGIN"),
    Symbol(SymbolType.ExternalSymbol, 0x04400008, "VI_WIDTH"),
    Symbol(SymbolType.ExternalSymbol, 0x0440000C, "VI_INTR"),
    Symbol(SymbolType.ExternalSymbol, 0x04400010, "VI_CURRENT"),
    Symbol(SymbolType.ExternalSymbol, 0x04400014, "VI_BURST"),
    Symbol(SymbolType.ExternalSymbol, 0x04400018, "VI_V_SYNC"),
    Symbol(SymbolType.ExternalSymbol, 0x0440001C, "VI_H_SYNC"),
    Symbol(SymbolType.ExternalSymbol, 0x04400020, "VI_LEAP"),
    Symbol(SymbolType.ExternalSymbol, 0x04400024, "VI_H_START"),
    Symbol(SymbolType.ExternalSymbol, 0x04400028, "VI_V_START"),
    Symbol(SymbolType.ExternalSymbol, 0x0440002C, "VI_V_BURST"),
    Symbol(SymbolType.ExternalSymbol, 0x04400030, "VI_X_SCALE"),
    Symbol(SymbolType.ExternalSymbol, 0x04400034, "VI_Y_SCALE"),
    Symbol(SymbolType.ExternalSymbol, 0x04500000, "AI_DRAM_ADDR"),
    Symbol(SymbolType.ExternalSymbol, 0x04500004, "AI_LEN"),
    Symbol(SymbolType.ExternalSymbol, 0x04500008, "AI_CONTROL"),
    Symbol(SymbolType.ExternalSymbol, 0x0450000C, "AI_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x04500010, "AI_DACRATE"),
    Symbol(SymbolType.ExternalSymbol, 0x04500014, "AI_BITRATE"),
    Symbol(SymbolType.ExternalSymbol, 0x04600000, "PI_DRAM_ADDR"),
    Symbol(SymbolType.ExternalSymbol, 0x04600004, "PI_CART_ADDR"),
    Symbol(SymbolType.ExternalSymbol, 0x04600008, "PI_RD_LEN"),
    Symbol(SymbolType.ExternalSymbol, 0x0460000C, "PI_WR_LEN"),
    Symbol(SymbolType.ExternalSymbol, 0x04600010, "PI_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x04600014, "PI_BSD_DOM1_LAT"),
    Symbol(SymbolType.ExternalSymbol, 0x04600018, "PI_BSD_DOM1_PWD"),
    Symbol(SymbolType.ExternalSymbol, 0x0460001C, "PI_BSD_DOM1_PGS"),
    Symbol(SymbolType.ExternalSymbol, 0x04600020, "PI_BSD_DOM1_RLS"),
    Symbol(SymbolType.ExternalSymbol, 0x04600024, "PI_BSD_DOM2_LAT"),
    Symbol(SymbolType.ExternalSymbol, 0x04600028, "PI_BSD_DOM2_PWD"),
    Symbol(SymbolType.ExternalSymbol, 0x0460002C, "PI_BSD_DOM2_PGS"),
    Symbol(SymbolType.ExternalSymbol, 0x04600030, "PI_BSD_DOM2_RLS"),
    Symbol(SymbolType.ExternalSymbol, 0x04700000, "RI_MODE"),
    Symbol(SymbolType.ExternalSymbol, 0x04700004, "RI_CONFIG"),
    Symbol(SymbolType.ExternalSymbol, 0x04700008, "RI_CURRENT_LOAD"),
    Symbol(SymbolType.ExternalSymbol, 0x0470000C, "RI_SELECT"),
    Symbol(SymbolType.ExternalSymbol, 0x04700010, "RI_REFRESH"),
    Symbol(SymbolType.ExternalSymbol, 0x04700014, "RI_LATENCY"),
    Symbol(SymbolType.ExternalSymbol, 0x04700018, "RI_RERROR"),
    Symbol(SymbolType.ExternalSymbol, 0x0470001C, "RI_WERROR"),
    Symbol(SymbolType.ExternalSymbol, 0x04800000, "SI_DRAM_ADDR"),
    Symbol(SymbolType.ExternalSymbol, 0x04800004, "SI_PIF_ADDR_RD64B_REG"),
    Symbol(SymbolType.ExternalSymbol, 0x04800010, "SI_PIF_ADDR_WR64B_REG"),
    Symbol(SymbolType.ExternalSymbol, 0x04800018, "SI_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x05000500, "ASIC_DATA"),
    Symbol(SymbolType.ExternalSymbol, 0x05000504, "ASIC_MISC_REG"),
    Symbol(SymbolType.ExternalSymbol, 0x05000508, "ASIC_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x0500050C, "ASIC_CUR_TK"),
    Symbol(SymbolType.ExternalSymbol, 0x05000510, "ASIC_BM_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x05000514, "ASIC_ERR_SECTOR"),
    Symbol(SymbolType.ExternalSymbol, 0x05000518, "ASIC_SEQ_STATUS"),
    Symbol(SymbolType.ExternalSymbol, 0x0500051C, "ASIC_CUR_SECTOR"),
    Symbol(SymbolType.ExternalSymbol, 0x05000520, "ASIC_HARD_RESET"),
    Symbol(SymbolType.ExternalSymbol, 0x05000524, "ASIC_C1_SO"),
    Symbol(SymbolType.ExternalSymbol, 0x05000528, "ASIC_HOST_SECBYTE"),
    Symbol(SymbolType.ExternalSymbol, 0x0500052C, "ASIC_C1_S2"),
    Symbol(SymbolType.ExternalSymbol, 0x05000530, "ASIC_SEC_BYTE"),
    Symbol(SymbolType.ExternalSymbol, 0x05000534, "ASIC_C1_S4"),
    Symbol(SymbolType.ExternalSymbol, 0x05000538, "ASIC_C1_S6"),
    Symbol(SymbolType.ExternalSymbol, 0x0500053C, "ASIC_CUR_ADDR"),
    Symbol(SymbolType.ExternalSymbol, 0x05000540, "ASIC_ID_REG"),
    Symbol(SymbolType.ExternalSymbol, 0x05000544, "ASIC_TEST_REG"),
    Symbol(SymbolType.ExternalSymbol, 0x05000548, "ASIC_TEST_PIN_SEL"),
]

def define_n64_symbols(bv: BinaryView, load_address: int):
    # Define our static code and data symbols
    for sym in MMIO:
        bv.define_auto_symbol(Symbol(sym.type, addr_to_64(sym.address | KSEG1_BASE), sym.name))
        
    for sym in STATIC_CODE_SYMBOLS:
        bv.define_auto_symbol(Symbol(sym.type, addr_to_64(sym.address | KSEG0_BASE), sym.name))

    for sym in STATIC_CODE_SYMBOLS_UNCACHED:
        bv.define_auto_symbol(Symbol(sym.type, addr_to_64(sym.address | KSEG1_BASE), sym.name))

    # Explicitly add function symbol at load address (start of code in ram)
    bv.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, load_address, "ramMain"))


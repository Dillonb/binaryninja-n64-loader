KSEG0_BASE = 0x80000000
KSEG1_BASE = 0xA0000000

MIPS_SEGMENTS = [
    (KSEG0_BASE, "KSEG0"),
    (KSEG1_BASE, "KSEG1"),
]

def addr_to_64(v):
    if v >> 31:
        return v | (0xFFFFFFFF << 32)
    else:
        return v
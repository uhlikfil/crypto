import binascii


def bin2txt(x: bytes) -> str:
    return x.decode()


def bin2hex(x: bytes) -> str:
    return bin2txt(binascii.hexlify(x))


def txt2bin(x: str) -> bytes:
    return x.encode()


def hex2bin(x: str) -> bytes:
    return binascii.unhexlify(x)


def hex2txt(x: str) -> str:
    return bin2txt(hex2bin(x))


def txt2hex(x: str) -> str:
    return bin2hex(txt2bin(x))


###########################
######## XOR UTILS ########
###########################

# http://www.macfreek.nl/memory/Letter_Distribution
LETTER_FREQ_EN: dict[str, float] = {
    " ": 0.1831685753,
    "e": 0.1021787708,
    "t": 0.0750999398,
    "a": 0.0655307059,
    "o": 0.0620055405,
    "n": 0.0570308374,
    "i": 0.0573425524,
    "s": 0.0532626738,
    "r": 0.0497199926,
    "h": 0.0486220925,
    "l": 0.0335616550,
    "d": 0.0335227377,
    "u": 0.0229520040,
    "c": 0.0226508836,
    "m": 0.0201727037,
    "f": 0.0197180888,
    "w": 0.0168961396,
    "g": 0.0163586607,
    "p": 0.0150311560,
    "y": 0.0146995463,
    "b": 0.0127076566,
    "v": 0.0078804815,
    "k": 0.0056916712,
    "x": 0.0014980832,
    "j": 0.0011440544,
    "q": 0.0008809302,
    "z": 0.0005979301,
}


###########################
######## AES UTILS ########
###########################
BLOCK_SIZE = 16

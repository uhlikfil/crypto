import string
from pathlib import Path

import pyaes

from report import ct, k, mark_exercise, pt
from utils import BLOCK_SIZE, bin2hex, bin2txt, hex2bin, txt2bin

SRC_DIR = Path(__file__).parents[2] / "lab2"


### Ex.2
def encrypt_aes_block(text: bytes, key: bytes) -> bytes:
    if len(text) != BLOCK_SIZE or len(key) != BLOCK_SIZE:
        raise ValueError(f"Can only encrypt blocks of size {BLOCK_SIZE} B")
    return pyaes.AESModeOfOperationECB(key).encrypt(text)


### Ex.3
def decrypt_aes_block(ct: bytes, key: bytes) -> bytes:
    if len(ct) != BLOCK_SIZE or len(key) != BLOCK_SIZE:
        raise ValueError(f"Can only decrypt blocks of size {BLOCK_SIZE} B")
    return pyaes.AESModeOfOperationECB(key).decrypt(ct)


### Ex.4
def pad(text: bytes) -> bytes:
    pad_size: int = BLOCK_SIZE - (len(text) % BLOCK_SIZE)
    to_append = pad_size.to_bytes(1, "big") * pad_size
    return text + to_append


### Ex.5
def unpad(text: bytes) -> bytes:
    pad_size: int = text[-1]
    return text[:-pad_size]


### Ex.6
def get_blocks(text: bytes) -> list[bytes]:
    return [
        text[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
        for i in range(len(text) // BLOCK_SIZE)
    ]


def encrypt_aes_ecb(text: bytes, key: bytes) -> bytes:
    if len(key) != BLOCK_SIZE:
        raise ValueError(f"Can only encrypt with a key of size {BLOCK_SIZE} B")
    padded = pad(text)
    ct = b""
    for block in get_blocks(padded):
        ct += encrypt_aes_block(block, key)
    return ct


### Ex.7
def decrypt_aes_ecb(text: bytes, key: bytes) -> bytes:
    if len(text) % BLOCK_SIZE != 0 or len(key) != BLOCK_SIZE:
        raise ValueError(f"Can only decrypt text of length of multiples of {BLOCK_SIZE} with a key of size {BLOCK_SIZE} B")  # fmt: skip
    pt = b""
    for block in get_blocks(text):
        pt += decrypt_aes_block(block, key)
    return unpad(pt)


### Ex.9
def welcome(name: str) -> bytes:
    msg = f"Your name is {name} and you are a user"
    key = b"RIDERSONTHESTORM"
    return encrypt_aes_ecb(txt2bin(msg), key)


# made for 4)
def extract_ct_block(wanted_text: str) -> str:
    return welcome(f"aa|{wanted_text}")[BLOCK_SIZE : 2 * BLOCK_SIZE]


### Ex.10
SECRET = "this should stay secret"


def hide_secret(x: str) -> bytes:
    salted = x + SECRET
    return encrypt_aes_ecb(txt2bin(salted), b"COOL T MAGIC KEY")


def discover_secret(known_secret="", current_block=0) -> str:
    block_start = current_block * BLOCK_SIZE
    block_end = block_start + BLOCK_SIZE
    padding = "A" * ((current_block + 1) * BLOCK_SIZE - 1 - len(known_secret))
    with_new_secret = hide_secret(padding)
    if len(padding) + len(known_secret) + 1 == len(with_new_secret):
        return known_secret
    for c in string.printable:
        attempt = hide_secret(padding + known_secret + c)[block_start:block_end]
        if attempt == with_new_secret[block_start:block_end]:
            known_secret += c
            break
    return discover_secret(known_secret, current_block + 1)


def main():
    mark_exercise(1)

    print(
        "I, Filip Uhlík, understand that cryptography is easy to mess up, and"
        "that I will not carelessly combine pieces of cryptographic ciphers to"
        "encrypt my users' data. I will not write crypto code myself, but defer to"
        "high-level libaries written by experts who took the right decisions for me,"
        "like NaCL."
    )

    mark_exercise(2)

    text = "90 miles an hour"
    key = "CROSSTOWNTRAFFIC"
    ciphertext = encrypt_aes_block(txt2bin(text), txt2bin(key))
    assert len(ciphertext) == BLOCK_SIZE, "Wrong! Size does matter!"
    print(f"The AES ciphertext of {pt(text)} with the key {k(key)} is {ct(bin2hex(ciphertext))}")  # fmt: skip

    mark_exercise(3)

    ct_hex = "fad2b9a02d4f9c850f3828751e8d1565"
    key = "VALLEYSOFNEPTUNE"
    plaintext = decrypt_aes_block(hex2bin(ct_hex), txt2bin(key))
    assert len(ciphertext) == BLOCK_SIZE, "Wrong! Size does matter!"
    print(f"The plaintext of {ct(ct_hex)} with the AES key {k(key)} is {pt(bin2txt(plaintext))}")  # fmt: skip

    mark_exercise(4)

    to_pad = "hello"
    padded = pad(txt2bin(to_pad))
    assert len(padded) % BLOCK_SIZE == 0, "This is baaad."
    print(f"{pt(to_pad)} with padding is {pt(bin2txt(padded))} (hex: {ct(bin2hex(padded))})")  # fmt: skip

    mark_exercise(5)

    to_unpad = b"hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    unpadded = unpad(to_unpad)
    print(f"The unpadded string is {pt(bin2txt(unpadded))}")

    mark_exercise(6)

    text = "Well, I stand up next to a mountain and I chop it down with the edge of my hand"
    key = "vdchldslghtrturn"
    ciphertext = encrypt_aes_ecb(txt2bin(text), txt2bin(key))
    print(f"The ciphertext of {pt(text)} with the key {k(key)} is {ct(bin2hex(ciphertext))}")  # fmt: skip

    mark_exercise(7)

    ciphertext = "792c2e2ec4e18e9d3a82f6724cf53848abb28d529a85790923c94b5c5abc34f50929a03550e678949542035cd669d4c66da25e59a5519689b3b4e11a870e7cea"
    key = "If the mountains"
    plaintext = decrypt_aes_ecb(hex2bin(ciphertext), txt2bin(key))
    print(f"The plaintext of {ct(ciphertext)} with the key {k(key)} is {pt(bin2txt(plaintext))}")  # fmt: skip

    mark_exercise(8)
    print("1) There are a lot of repeating lines, it might mean the lyrics aren't too rich")  # fmt: skip
    print("2) The last block is probably added padding")
    with open(SRC_DIR / "text1.hex", "r") as f:
        text1_hex_lines = f.readlines()
    text1_hex_lines[0], text1_hex_lines[2] = text1_hex_lines[2], text1_hex_lines[0]
    print("3) Order has been restored")
    text1_hex = "".join(map(str.strip, text1_hex_lines))
    key = "TLKNGBTMYGNRTION"
    plaintext = decrypt_aes_ecb(hex2bin(text1_hex), txt2bin(key))
    first_line = bin2txt(plaintext).split("\n")[0]
    print(f"4) The correct first line is {pt(first_line)}")

    mark_exercise(9)

    print(f"1) Welcome function implemented")
    jim = welcome("Jim")
    print(f"2) Welcome Jim ciphertext: {ct(bin2hex(jim))}")

    # the message length is multiple of block size, so empty name forces the 16 padding
    padding_ct = welcome("")[-BLOCK_SIZE:]
    print(f"3) A ciphertext block of all 16 bytes: {ct(bin2hex(padding_ct))}")

    admin_ct = extract_ct_block("you are an admin")
    print(f'4) A ciphertext block of {pt("you are an admin")}: {ct(bin2hex(admin_ct))}')

    _and = extract_ct_block("_" * (BLOCK_SIZE - 5) + " and ")
    final_ct = jim + _and + admin_ct + padding_ct
    print(f"5) The crafted ciphertext is {ct(bin2hex(final_ct))}")

    plaintext = decrypt_aes_ecb(final_ct, b"RIDERSONTHESTORM")
    print(f"6) The plaintext of the crafted ciphertext is {pt(bin2txt(plaintext))}")
    print(
        "7) If the ciphertext of such message, easily influencable by an attacker, "
        "was used for an actual authorization, it could lead to some kind of privilege escalation"
    )

    mark_exercise(10)

    expected = "45a306391112e09639cc44fa4d53c79ec90162749b6055bbc3d0811c0da6bd9bdf3dccce5ff98e742ffdc33a1c8e84b9d47e0182d8fa07c9291b25d8dab01199"
    assert bin2hex(hide_secret("just listen find the magic key")) == expected, "Oh no"

    cracked = discover_secret()
    assert cracked == SECRET, "Damn, this does not work at all"
    print(f"Yay, I can now crack the {k('hide_secret')} function")
    print("The next cracked byte would be always 1 because that's the padding added after the secret message")  # fmt: skip


if __name__ == "__main__":
    main()

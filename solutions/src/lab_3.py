import os

from lab_1 import xor
from lab_2 import decrypt_aes_block, encrypt_aes_block, get_blocks, pad, unpad
from report import ct, k, mark_exercise, pt
from utils import BLOCK_SIZE, bin2hex, bin2txt, hex2bin, txt2bin


### Ex.1
def encrypt_aes_cbc(text: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != BLOCK_SIZE or len(iv) != BLOCK_SIZE:
        raise ValueError(f"Can only encrypt with a key and IV of size {BLOCK_SIZE} B")
    padded = pad(text)
    ct = b""
    last_block = iv
    for pt_block in get_blocks(padded):
        to_encrypt = xor(pt_block, last_block)
        last_block = encrypt_aes_block(to_encrypt, key)
        ct += last_block
    return ct


### Ex.2
def decrypt_aes_cbc(text: bytes, key: bytes, iv: bytes, keep_padding=False) -> bytes:
    if len(text) % BLOCK_SIZE != 0 or len(key) != BLOCK_SIZE or len(iv) != BLOCK_SIZE:
        raise ValueError(f"Can only decrypt text of length of multiples of {BLOCK_SIZE} with a key and IV of size {BLOCK_SIZE} B")  # fmt: skip
    pt = b""
    last_block = iv
    for ct_block in get_blocks(text):
        decrypted = decrypt_aes_block(ct_block, key)
        pt += xor(decrypted, last_block)
        last_block = ct_block
    return pt if keep_padding else unpad(pt)


### Ex.3
def letter_diff(l1, l2) -> int:
    return ord(l1) ^ ord(l2)


### Ex.4
def generate_iv() -> bytes:
    return os.urandom(BLOCK_SIZE)


### Ex.5
SECRET = b"this data is top secret, can you decrypt it?"
KEY = b"nzbighzuxgjsoajg"


def server_encrypt() -> tuple[bytes, bytes]:
    iv = generate_iv()
    return iv, encrypt_aes_cbc(SECRET, KEY, iv)


def server_decrypt(text: bytes, iv: bytes) -> bool:
    pt = decrypt_aes_cbc(text, KEY, iv, keep_padding=True)
    pad_size: int = pt[-1]
    for c in pt[-pad_size:]:
        if c != pad_size:
            return False
    return True


### Ex.6
def crack_block(cipher_block: bytes, iv: bytes, known_pt="", offset=0) -> str:
    if len(known_pt) == BLOCK_SIZE:
        return known_pt
    pos = len(known_pt) + 1
    iv_copy = bytearray(iv)
    for i in range(1, pos):
        iv_copy[-i] = iv_copy[-i] ^ ord(known_pt[-i]) ^ pos
    for test in range(0 + offset, 256):
        iv_ba = bytearray(iv_copy)
        iv_ba[-pos] = iv_ba[-pos] ^ test
        iv_mod = bytes(iv_ba)
        if server_decrypt(cipher_block, iv_mod):
            char = test ^ pos
            known_pt = f"{chr(char)}{known_pt}"
            return crack_block(cipher_block, iv, known_pt, 0)
    return crack_block(cipher_block, iv, "", 1)


def crack_oracle() -> str:
    iv, cipher = server_encrypt()
    pt = ""
    tmp_iv = iv
    for block in get_blocks(cipher):
        pt_block = crack_block(block, tmp_iv)
        pt += pt_block
        tmp_iv = block
    return pt


def main():
    mark_exercise(1)

    plaintext = "we are always running for the thrill of it"
    key = "WALKINGONADREAM."
    iv_hex = "a1b27b4eeef364f9da74a8c06edbd771"
    ct_bin = encrypt_aes_cbc(txt2bin(plaintext), txt2bin(key), hex2bin(iv_hex))
    print(f"The ciphertext of {pt(plaintext)} with the key {k(key)} is {ct(bin2hex(ct_bin))}")  # fmt: skip

    mark_exercise(2)

    decrypted = decrypt_aes_cbc(ct_bin, txt2bin(key), hex2bin(iv_hex))
    assert bin2txt(decrypted) == plaintext, "CBC does not work"
    print(f"Decrypted back to {pt(bin2txt(decrypted))}")

    mark_exercise(3)

    plaintext = "welcome to this car"
    c = plaintext[16]
    print(f"a) The first byte of the second block is: {k(c)}, ascii decimal: {k(ord(c))}, binary: {k(bin(ord(c)))}")  # fmt: skip
    print(f"To change the byte into the letter {k('b')} ({k(bin(ord('b')))}), we'd need to change the rightmost bit to 0")  # fmt: skip
    key = b"nckdlgyzsklvheba"
    iv_bin = hex2bin("fbd71a63197605dde3ac8bce86c1ead7")
    ct_bin = encrypt_aes_cbc(txt2bin(plaintext), key, iv_bin)
    print(f"b) The ciphertext is {ct(bin2hex(ct_bin))}")
    print("c) The first byte of the second block is xored with the first byte of the ciphertext when decrypting")  # fmt: skip
    print("Because of that, the bit flips we do in the first block of ciphertext propagate to the second block of decrypted text")  # fmt: skip
    print("We can use XOR operation to flip the bit")
    ct_ba = bytearray(ct_bin)  # XOR the first byte with 1 to flip the rightmost bit
    ct_ba[0] = ct_bin[0] ^ 1
    ct_bin_b = bytes(ct_ba)
    print(f"The modified ciphertext is {ct(bin2hex(ct_bin_b))}")
    decrypted_b = decrypt_aes_cbc(ct_bin_b, key, iv_bin)
    print(f"After decrypting it we get {pt(decrypted_b)}")
    print(f"The first block is all messed up by the bit flip, but the second block starts with {pt(bin2txt(decrypted_b[-3:]))}")  # fmt: skip
    print("d) To change the letter we can flip more bits by XORing the ciphertext with a different value")  # fmt: skip
    print("- the value is the difference between the letters we want to change")
    ct_ba = bytearray(ct_bin)
    ct_ba[0] = ct_bin[0] ^ letter_diff("c", "w")
    ct_bin_w = bytes(ct_ba)
    print(f"The modified ciphertext is {ct(bin2hex(ct_bin_w))}")
    decrypted_w = decrypt_aes_cbc(ct_bin_w, key, iv_bin)
    print(f"After decrypting it we get {pt(decrypted_w)}")

    mark_exercise(4)

    print("Cryptographically-secure pseudorandom number generator")
    print("The non-CS PRNG is a number generator which looks random, but is produced by a deterministic algorithm")  # fmt: skip
    print("On the other hand, CSPRNG should be unpredictable. That's why it is better suited for cryptography")  # fmt: skip
    print("If the attacker could guess the next IV we would use, our cipher would be in danger")  # fmt: skip

    mark_exercise(5)

    iv, test = server_encrypt()
    print(f"The server has generated IV {k(bin2hex(iv))} and encrypted text {ct(bin2hex(test))}")  # fmt: skip
    assert server_decrypt(test, iv), "The server sucks"
    assert not server_decrypt(pad(b"very wrong ciphertext"), iv), "The server sucks"
    print("And can signal successful decryption")

    mark_exercise(6)
    print(f"After a lot of trial and error I have finally created the {k('crack_block')} function which can handle the padding by backtracking")  # fmt: skip
    print("I'm not sure if the backtracking is done the way it was meant by the assignment, but it works...")  # fmt: skip


if __name__ == "__main__":
    main()

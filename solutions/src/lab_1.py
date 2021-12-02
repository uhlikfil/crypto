import math
import string
import sys
from pathlib import Path

from report import ct, k, mark_exercise, pt
from utils import LETTER_FREQ_EN, bin2hex, bin2txt, hex2bin, txt2bin

SRC_DIR = Path(__file__).parents[2] / "lab1"


### Ex.1
def repeat_key(key: bytes, wanted_len: int) -> bytes:
    repeats = math.ceil(wanted_len / len(key))
    return (key * repeats)[:wanted_len]


def xor(text: bytes, key: bytes, byteorder=sys.byteorder) -> bytes:
    if len(key) > len(text):  # always have text as the longer string
        text, key = key, text
    length = len(text)
    key = repeat_key(key, length)
    int_text = int.from_bytes(text, byteorder)
    int_key = int.from_bytes(key, byteorder)
    return (int_text ^ int_key).to_bytes(length, byteorder)


### Ex.4
def frequence_diff(text: str, compare_to: dict = LETTER_FREQ_EN) -> int:
    size = len(text)
    text_counts = {}
    for char in text:
        text_counts[char] = text_counts.setdefault(char, 0) + 1
    text_freq = {char: count / size for char, count in text_counts.items()}
    return sum(abs(freq - text_freq.get(char, 0)) for char, freq in compare_to.items())


def auto_decode_bin(text: bytes) -> tuple[str, str]:
    best_freq_diff = 10
    for key in string.printable:
        plaintext = bin2txt(xor(text, txt2bin(key)))
        f_diff = frequence_diff(plaintext)
        if f_diff < best_freq_diff:
            best_freq_diff = f_diff
            best_key = key
            best_plaintext = plaintext
    return best_key, best_plaintext


### Ex.5
def auto_decode_bin_multi_letter_key(text: bytes, key_len: int) -> tuple[str, str]:
    key_parts = []
    pt_parts = []
    for i in range(key_len):
        sub_ct = text[i::key_len]
        key, pt = auto_decode_bin(sub_ct)
        key_parts.append(key)
        pt_parts.append(pt)
    key = "".join(key_parts)
    plaintext = ""
    for i in range(len(pt_parts[0])):
        for part in pt_parts:
            if i < len(part):
                plaintext += part[i]
    return key, plaintext


### Ex.6
def hamming(str1: bytes, str2: bytes) -> int:
    """https://idafchev.github.io/crypto/2017/04/13/crypto_part1.html"""
    xored = xor(str1, str2)
    return bin(int(bin2hex(xored), 16)).count("1")


def find_xor_keysize(ciphertext: bytes, block_cnt: int, minsize=2, maxsize=100) -> int:
    """https://idafchev.github.io/crypto/2017/04/13/crypto_part1.html"""
    hamming_dict = {}
    if (block_cnt * maxsize) > len(ciphertext):
        raise ValueError("Lower the block_count or the key maxsize!")

    for key_length in range(minsize, maxsize):
        blocks = []
        for i in range(block_cnt):
            blocks.append(ciphertext[i * key_length : (i + 1) * key_length])
        hd = []
        for i in range(block_cnt - 1):
            for j in range(i + 1, block_cnt):
                hd.append(hamming(blocks[i], blocks[j]))

        hd_average = float(sum(hd)) / len(hd)
        hd_normalized = hd_average / key_length
        hamming_dict[key_length] = hd_normalized

    sorted_list_tuples = sorted(hamming_dict.items(), key=lambda x: x[1])
    return sorted_list_tuples[0][0]


def main():
    mark_exercise(1)

    text = b"everything remains raw"
    key = b"word up"
    ciphertext = bin2hex(xor(text, key))
    assert ciphertext == "121917165901181e01154452101d16061c1700071100", "I can't even xor, put me in Jail"  # fmt: skip

    text = "the world is yours"
    key = "illmatic"
    ciphertext = bin2hex(xor(txt2bin(text), txt2bin(key)))
    print(f"The ciphertext of {pt(text)} against the key {k(key)} is {ct(ciphertext)}")

    mark_exercise(2)

    print(
        "The ciphertext '404b48484504404b48484504464d4848045d4b'"
        "contains a repeating pattern '404b48484504' at the beginning."
        "Because it was encrypted with only a single letter key,"
        "it means that the plaintext also has a repetition at the beginning,"
        "probably two exact same words. Another visible pattern is '4848' at indices 4, 16, 28."
        "This means that there are two identical letters at those positions."
    )
    ct_hex = "404b48484504404b48484504464d4848045d4b"
    key = "$"
    plaintext = bin2txt(xor(hex2bin(ct_hex), txt2bin(key)))
    print(f"The plaintext of {ct(ct_hex)} against the key {k(key)} is {pt(plaintext)}")

    mark_exercise(3)

    with open(SRC_DIR / "text1.hex", "r") as f:
        text1_hex_lines = f.readlines()

    for key in string.printable:
        plaintext = bin2txt(xor(hex2bin(text1_hex_lines[0].strip()), txt2bin(key)))
        if key == "M":  # now I know and don't want to spam the stdout
            print(f"{k(key)}: {pt(plaintext)}")

    mark_exercise(4)

    text1_hex = "".join(map(str.strip, text1_hex_lines))
    key, plaintext = auto_decode_bin(hex2bin(text1_hex))
    assert key == "M", "Oops, auto-decode does not work"
    print(f"Ok Ok, the key was indeed {k(key)}")
    print(f"\n{plaintext[:128]}...")

    mark_exercise(5)

    with open(SRC_DIR / "text2.hex", "r") as f:
        text2_hex_lines = f.readlines()
    text2_hex = "".join(map(str.strip, text2_hex_lines))
    key, plaintext = auto_decode_bin_multi_letter_key(hex2bin(text2_hex), 10)
    first_line = bin2txt(xor(hex2bin(text2_hex_lines[0].strip()), txt2bin(key)))
    print(f"The multi-letter xor key is {k(key)}, the first line is: {pt(first_line)}")
    print(f"\n{plaintext[:128]}...")

    mark_exercise(6)

    with open(SRC_DIR / "text3.hex", "r") as f:
        text3_hex_lines = f.readlines()
    text3_hex = "".join(map(str.strip, text3_hex_lines))
    text3_bin = hex2bin(text3_hex)
    key_len = find_xor_keysize(text3_bin, 4)
    key, plaintext = auto_decode_bin_multi_letter_key(text3_bin, key_len)
    first_line = bin2txt(xor(hex2bin(text3_hex_lines[0].strip()), txt2bin(key)))
    print(f"The key length is {k(key_len)}, the key is {k(key)}, the first line is: {pt(first_line)}")  # fmt: skip
    print(f"\n{plaintext[:128]}...")

    ### Ex.bonus
    mark_exercise("(bonus)")

    print(f'Here comes the brand new {pt("Flava In Ya Ear")}')


if __name__ == "__main__":
    main()

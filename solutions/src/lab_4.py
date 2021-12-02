from report import ct, mark_exercise
from utils import bin2hex, hex2bin

INT_SIZE = 32

w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
f = 1812433253

### Ex.1
class MT:
    index: int
    v = [0] * n

    def __init__(self, seed) -> None:
        self.seed(seed)

    def seed(self, seed):
        self.v[0] = seed
        for i in range(1, n):
            self.v[i] = (f * (self.v[i - 1] ^ (self.v[i - 1] >> 30)) + i) & 0xFFFFFFFF
        self.index = n

    def next(self) -> int:
        if self.index == n:
            self.v = MT.twist(self.v)
            self.index = 0
        x = self.v[self.index]
        self.index += 1
        return MT.temper(x)

    @staticmethod
    def twist(v_prev: list[int]) -> list[int]:
        v = v_prev.copy()
        for i in range(n):
            x = (v[i] & 0x80000000) ^ (v[(i + 1) % n] & 0x7FFFFFFF)
            xA = x >> 1
            if x & 0x00000001:
                xA = xA ^ a
            v[i] = v[(i + m) % n] ^ xA
        return v

    @staticmethod
    def temper(x) -> int:
        y1 = x ^ ((x >> u) & d)
        y2 = y1 ^ ((y1 << s) & b)
        y3 = y2 ^ ((y2 << t) & c)
        z = y3 ^ (y3 >> l)
        return z


### Ex.2
def to_bits(x: int) -> list[int]:
    return [int(i) for i in format(x, "#034b")[2:]]


def from_bits(x: list[int]) -> int:
    return int("".join(str(i) for i in x), 2)


def untemper(z) -> int:
    # for the first and last operation
    def revert_right_shift_xor(res: list[int], shift: int) -> list[int]:
        orig = res[:shift]
        for i in range(shift, INT_SIZE):
            orig += [res[i] ^ orig[i - shift]]
        return orig

    # for the second and third operation
    def revert_left_shift_xor_mask(res: list[int], shift: int, mask: int) -> list[int]:
        orig = to_bits((mask ^ d) & from_bits(res))
        mask_b = to_bits(mask)
        for i in range(INT_SIZE - 1, -1, -1):
            if mask_b[i] == 1:
                orig[i] = res[i] ^ orig[i + shift]
        return orig

    zb = to_bits(z)
    # get y3 by reverting z = y3 ^ (y3 >> l)
    y3 = revert_right_shift_xor(zb, l)
    # get y2 by reverting y3 = y2 ^ ((y2 << t) & c)
    y2 = revert_left_shift_xor_mask(y3, t, c)
    # get y1 by reverting y2 = y1 ^ ((y1 << s) & b) - same as the above, just different constants
    y1 = revert_left_shift_xor_mask(y2, s, b)
    # get x by reverting y1 = x ^ ((x >> u) & d) - same as the first one
    x = revert_right_shift_xor(y1, u)
    return from_bits(x)


def reverse_matrix_multiplication(xA):
    x = xA << 1
    x = x & d
    if xA & 0x80000000:
        shifted_a_with_one_at_the_right = ((a << 1) & d) + 1
        x = x ^ shifted_a_with_one_at_the_right
    return x


def untwist(v: list[int]) -> list[int]:
    v_prev = v.copy()
    for i in range(n - 1, -2, -1):
        xA = v_prev[i] ^ v_prev[(i + m) % n]
        x = reverse_matrix_multiplication(xA)
        if i != -1:  # thanks Tondo Hrusko
            v_prev[i] = (x & 0x80000000) | (v_prev[i] & 0x7FFFFFFF)
        v_prev[(i + 1) % n] = (x & 0x7FFFFFFF) | (v_prev[(i + 1) % n] & 0x80000000)
    return v_prev


### Ex.3
class PwResetToken:
    def __init__(self, seed: int) -> None:
        self.mt = MT(seed)

    def gen_token(self) -> str:
        nums = [self.mt.next() for _ in range(16)]
        return PwResetToken.concat_as_hex(nums)

    @staticmethod
    def concat_as_hex(numbers: list[int]) -> str:
        token = ""
        for num in numbers:
            token += bin2hex(num.to_bytes(4, "big"))
        return token


### Ex.3 split the token into the original integers
def split_token(token: str) -> list[int]:
    parts = [token[i * 8 : (i + 1) * 8] for i in range(16)]
    return [int.from_bytes(hex2bin(p), "big") for p in parts]


def main():
    mark_exercise(1)

    mt = MT(seed=123456789)
    expected_vector_start = [123456789, 2139825738, 2037464729, 1515522555]
    assert mt.v[:4] == expected_vector_start, "Wrong MT vector!"
    assert mt.v[-1] == 3075821708, "Wrong MT vector!"
    print("a) b) c) Mersenne Twister seed implemented correctly")
    print("\nd)")
    print(ct("Explain what the operations with masks 0x80000000 and 0x7fffffff mean:"))
    print("The operation takes the left-most bit from the v[i] and the rest of the bits from the v[(i+1)%n] numbers in v")  # fmt: skip
    print(ct("Explain why xA in the pseudo-code above contains the result of the multiplication:"))  # fmt: skip
    print("The shifted diagonal in the matrix represents the bit right shift")  # fmt: skip
    print("When the last element of the vector is 1 (the if mask condition), then the last row of the matrix is taken into count - sum in base 2 is the equivalent of xor operation")  # fmt: skip
    print(ct("Give a necessary and sufficient condition on the constant a, for A to be invertible. Is it satisfied by our constant a = 0x9908B0DF?"))  # fmt: skip
    print("The determinant of the matrix must be non-zero. That's the case if the matrix contains only linearly independent rows and columns - a_31 must be 1. It is satisfied by a\n")  # fmt: skip

    expected_next = [2288500408, 4254805660, 2294099250, 56498137]
    for i in expected_next:
        assert mt.next() == i, "Wrong next returned!"
    print("e) f) g) Mersenne Twister next implemented correctly")

    mark_exercise(2)
    x = 48945231
    assert x == untemper(MT.temper(x)), "untemper does not work!"
    print("a) Assert passed, untemper implemented correctly, look into temper_visu.txt to see what you showed us on the last lecture :-)")  # fmt: skip
    print("b) Multiplication of the two matrices produces an identity matrix")
    assert untwist(MT.twist(mt.v)) == mt.v, "untwist does not work!"
    print("c) Assert passed, untwist implemented correctly")

    mark_exercise(3)

    t_gen = PwResetToken(123456789)
    first_token = t_gen.gen_token()
    assert first_token.startswith("8867beb8fd9b2e9c88bd2d32035e17d9"), "Token generator does not work!"  # fmt: skip
    print("a) b) Assert passed, PwResetToken implemented correctly")

    to_assert = split_token(first_token)[: len(expected_next)]
    assert to_assert == expected_next, "split_token does not work"

    print("c) Burning the token generator...")
    for _ in range(1023):
        t_gen.gen_token()
    print("Saving the next token...")
    secret_token = t_gen.gen_token()
    print(
        "To recover the token, we can first recover the internal state of the MT, "
        "by getting 624 (the size of the internal list) numbers from it and untempering them"
    )
    mt_internal = []
    for _ in range(n // 16):
        mt_internal.extend(split_token(t_gen.gen_token()))
    mt_internal = [untemper(num) for num in mt_internal]
    print("Then we untwist and temper the list again to see the numbers that were generated before")  # fmt: skip
    untwisted = untwist(mt_internal)
    tempered = [MT.temper(x) for x in untwisted]
    print("Somehow it's the last elements of the list, I don't really know why...")
    recovered_token = PwResetToken.concat_as_hex(tempered[-16:])

    assert recovered_token == secret_token, "Nope, that did not work..."
    print("Assert passed, the token has been recovered")


if __name__ == "__main__":
    main()
